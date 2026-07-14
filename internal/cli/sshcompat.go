package cli

// sshcompat.go makes botsign a drop-in for the four `ssh-keygen -Y`
// operations git performs, so a repo can set gpg.ssh.program=botsign and
// need no OpenSSH toolchain at all:
//
//	-Y sign             — git commit/tag signing (writes <file>.sig)
//	-Y find-principals  — git verify-commit, step 1
//	-Y verify           — git verify-commit, step 2 (payload on stdin)
//	-Y check-novalidate — git's fallback when no principal matches
//
// The argument shapes mirror what git's gpg-interface.c passes; unknown
// flags fail loudly rather than being misinterpreted, because a signing
// backend that guesses is worse than one that stops.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JaydenCJ/botsign/internal/sshsig"
	"github.com/JaydenCJ/botsign/internal/store"
)

// compatArgs is the parsed `ssh-keygen -Y` style argument list.
type compatArgs struct {
	mode       string   // sign, verify, find-principals, check-novalidate
	namespace  string   // -n
	file       string   // -f: key file (sign) or allowed_signers (verify)
	principal  string   // -I
	sigPath    string   // -s
	literalKey bool     // -U: -f holds a public key; private key is ours to find
	positional []string // sign: the payload file
}

func parseCompat(args []string) (*compatArgs, error) {
	c := &compatArgs{}
	for i := 0; i < len(args); i++ {
		needsValue := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", args[i])
			}
			i++
			return args[i], nil
		}
		var err error
		switch args[i] {
		case "-Y":
			c.mode, err = needsValue()
		case "-n":
			c.namespace, err = needsValue()
		case "-f":
			c.file, err = needsValue()
		case "-I":
			c.principal, err = needsValue()
		case "-s":
			c.sigPath, err = needsValue()
		case "-U":
			c.literalKey = true
		case "-O":
			// ssh-keygen options like hashalg=…; accepted and ignored.
			_, err = needsValue()
		default:
			if strings.HasPrefix(args[i], "-O") {
				// git passes options glued: `-Overify-time=…`. Ignored too.
				continue
			}
			if len(args[i]) > 0 && args[i][0] == '-' {
				return nil, fmt.Errorf("unsupported ssh-keygen flag %q", args[i])
			}
			c.positional = append(c.positional, args[i])
		}
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

// runCompat dispatches the ssh-keygen compatibility interface. Exit codes
// follow ssh-keygen: 0 success, 1 failure — git checks them.
func runCompat(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c, err := parseCompat(args)
	if err != nil {
		fmt.Fprintf(stderr, "botsign (ssh-keygen mode): %v\n", err)
		return ExitUsage
	}
	switch c.mode {
	case "sign":
		err = compatSign(c)
	case "verify":
		err = compatVerify(c, stdin, stdout)
	case "find-principals":
		err = compatFindPrincipals(c, stdout)
	case "check-novalidate":
		err = compatCheckNovalidate(c, stdin, stdout)
	default:
		fmt.Fprintf(stderr, "botsign (ssh-keygen mode): unsupported operation %q\n", c.mode)
		return ExitUsage
	}
	if err != nil {
		fmt.Fprintf(stderr, "botsign (ssh-keygen mode): %v\n", err)
		return ExitFail
	}
	return ExitOK
}

// compatSign signs the payload file and writes `<file>.sig`, exactly like
// `ssh-keygen -Y sign`.
func compatSign(c *compatArgs) error {
	if c.namespace == "" {
		return errors.New("sign needs a namespace (-n)")
	}
	if c.file == "" {
		return errors.New("sign needs a key file (-f)")
	}
	if len(c.positional) != 1 {
		return fmt.Errorf("sign needs exactly one payload file, got %d", len(c.positional))
	}
	keyData, err := os.ReadFile(c.file)
	if err != nil {
		return err
	}
	priv, err := loadSigningKey(keyData, c.literalKey)
	if err != nil {
		return err
	}
	payload, err := os.ReadFile(c.positional[0])
	if err != nil {
		return err
	}
	sig, err := sshsig.Sign(priv, c.namespace, payload)
	if err != nil {
		return err
	}
	return os.WriteFile(c.positional[0]+".sig", sig, 0o644)
}

// loadSigningKey resolves the private key. With -U the file holds a
// public key (git's literal `key::…` config) and the matching private key
// is looked up in the keystore; otherwise the file is the private key.
func loadSigningKey(keyData []byte, literal bool) (ed25519.PrivateKey, error) {
	if !literal {
		priv, _, err := sshsig.ParsePrivate(keyData)
		return priv, err
	}
	pub, _, err := sshsig.ParseAuthorized(string(keyData))
	if err != nil {
		return nil, fmt.Errorf("-U key file: %v", err)
	}
	st, err := resolveStore("", ".")
	if err != nil {
		return nil, err
	}
	sess, err := st.FindByPublicKey(sshsig.EncodePublicBlob(pub))
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, fmt.Errorf("no session in %s owns key %s", st.Root, sshsig.Fingerprint(pub))
	}
	return st.LoadPrivate(sess.ID)
}

// compatVerify mirrors `ssh-keygen -Y verify`: the payload arrives on
// stdin, and the signature must (a) verify cryptographically, (b) be in
// the requested namespace, and (c) belong to a key the allowed_signers
// file grants to the requested principal in that namespace.
func compatVerify(c *compatArgs, stdin io.Reader, stdout io.Writer) error {
	if c.file == "" || c.sigPath == "" || c.principal == "" || c.namespace == "" {
		return errors.New("verify needs -f allowed_signers, -I principal, -n namespace, and -s signature")
	}
	sigData, err := os.ReadFile(c.sigPath)
	if err != nil {
		return err
	}
	payload, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	pub, err := sshsig.Verify(sigData, c.namespace, payload)
	if err != nil {
		return err
	}
	entries, err := readAllowedSigners(c.file)
	if err != nil {
		return err
	}
	keyBlob := sshsig.EncodePublicBlob(pub)
	for _, entry := range entries {
		if !entry.PermitsNamespace(c.namespace) || string(entry.KeyBlob) != string(keyBlob) {
			continue
		}
		for _, principal := range entry.Principals {
			if principal == c.principal {
				fmt.Fprintf(stdout, "Good \"%s\" signature for %s with ED25519 key %s\n",
					c.namespace, c.principal, sshsig.Fingerprint(pub))
				return nil
			}
		}
	}
	return fmt.Errorf("key %s is not allowed for principal %q in namespace %q",
		sshsig.Fingerprint(pub), c.principal, c.namespace)
}

// compatFindPrincipals mirrors `ssh-keygen -Y find-principals`: print the
// principals the allowed_signers file grants to the signature's key.
func compatFindPrincipals(c *compatArgs, stdout io.Writer) error {
	if c.file == "" || c.sigPath == "" {
		return errors.New("find-principals needs -f allowed_signers and -s signature")
	}
	sigData, err := os.ReadFile(c.sigPath)
	if err != nil {
		return err
	}
	sig, err := sshsig.Decode(sigData)
	if err != nil {
		return err
	}
	entries, err := readAllowedSigners(c.file)
	if err != nil {
		return err
	}
	keyBlob := sshsig.EncodePublicBlob(sig.PublicKey)
	found := false
	for _, entry := range entries {
		if string(entry.KeyBlob) != string(keyBlob) {
			continue
		}
		for _, principal := range entry.Principals {
			fmt.Fprintln(stdout, principal)
			found = true
		}
	}
	if !found {
		return fmt.Errorf("no principals matched key %s", sshsig.Fingerprint(sig.PublicKey))
	}
	return nil
}

// compatCheckNovalidate mirrors `ssh-keygen -Y check-novalidate`: confirm
// the signature is structurally and cryptographically sound without
// consulting any principal list.
func compatCheckNovalidate(c *compatArgs, stdin io.Reader, stdout io.Writer) error {
	if c.sigPath == "" || c.namespace == "" {
		return errors.New("check-novalidate needs -n namespace and -s signature")
	}
	sigData, err := os.ReadFile(c.sigPath)
	if err != nil {
		return err
	}
	payload, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	pub, err := sshsig.Verify(sigData, c.namespace, payload)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Good \"%s\" signature with ED25519 key %s\n", c.namespace, sshsig.Fingerprint(pub))
	return nil
}

func readAllowedSigners(path string) ([]*store.AllowedSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return store.ParseAllowedSigners(data)
}
