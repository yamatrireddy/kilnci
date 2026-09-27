// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	dek := testKey(t)
	aad := AAD{OrgID: "org1", ScopeKind: ScopeProject, ScopeID: "proj1", Name: "TOKEN", DEKVersion: 3, ValueVersion: 1}
	for _, pt := range [][]byte{[]byte("abcd"), bytes.Repeat([]byte{0xff}, 64<<10)} {
		sealed, err := Seal(dek, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed, pt) {
			t.Fatal("sealed value contains the plaintext")
		}
		got, err := Open(dek, sealed, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("round trip changed the value")
		}
	}
}

func TestSeal_FreshNonceEachTime(t *testing.T) {
	dek := testKey(t)
	aad := testAAD()
	a, _ := Seal(dek, []byte("same-value"), aad)
	b, _ := Seal(dek, []byte("same-value"), aad)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same value are identical")
	}
}

// T-62: a ciphertext moved to any other org, scope, name, or DEK version
// must not open.
func TestOpen_RejectsAnyOtherContext(t *testing.T) {
	dek := testKey(t)
	aad := testAAD()
	sealed, err := Seal(dek, []byte("value"), aad)
	if err != nil {
		t.Fatal(err)
	}
	with := func(f func(*AAD)) AAD { a := aad; f(&a); return a }
	for name, other := range map[string]AAD{
		"org":        with(func(a *AAD) { a.OrgID = "org2" }),
		"scope kind": with(func(a *AAD) { a.ScopeKind = ScopeOrg }),
		"scope":      with(func(a *AAD) { a.ScopeID = "proj2" }),
		"name":       with(func(a *AAD) { a.Name = "TOKEN2" }),
		"dek":        with(func(a *AAD) { a.DEKVersion = 2 }),
		// An older ciphertext of the same secret cannot be restored in place.
		"value version": with(func(a *AAD) { a.ValueVersion = 2 }),
		// Netstrings keep field boundaries unambiguous.
		"shifted": with(func(a *AAD) { a.OrgID, a.ScopeID = "org1p", "roj1" }),
	} {
		if _, err := Open(dek, sealed, other); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
	if _, err := Open(testKey(t), sealed, aad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("other key: err = %v, want ErrDecrypt", err)
	}
}

func TestOpen_RejectsTamperingAndMalformedInput(t *testing.T) {
	dek := testKey(t)
	aad := testAAD()
	sealed, _ := Seal(dek, []byte("value"), aad)
	for i := range sealed {
		c := bytes.Clone(sealed)
		c[i] ^= 0x01
		if _, err := Open(dek, c, aad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flipped byte %d: err = %v, want ErrDecrypt", i, err)
		}
	}
	for name, in := range map[string][]byte{
		"empty":     nil,
		"short":     sealed[:20],
		"truncated": sealed[:len(sealed)-1],
	} {
		if _, err := Open(dek, in, aad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
}

func TestSeal_RejectsWrongKeySize(t *testing.T) {
	if _, err := Seal(make([]byte, 16), []byte("v"), testAAD()); err == nil {
		t.Fatal("AES-128 key accepted")
	}
	if _, err := Open(make([]byte, 31), make([]byte, 64), testAAD()); err == nil {
		t.Fatal("31-byte key accepted")
	}
}

func testAAD() AAD {
	return AAD{OrgID: "org1", ScopeKind: ScopeProject, ScopeID: "proj1", Name: "TOKEN", DEKVersion: 1, ValueVersion: 1}
}

func TestSealOpen_RejectIncompleteContext(t *testing.T) {
	dek := testKey(t)
	sealed, _ := Seal(dek, []byte("value"), testAAD())
	for name, f := range map[string]func(*AAD){
		"no org":        func(a *AAD) { a.OrgID = "" },
		"no scope":      func(a *AAD) { a.ScopeID = "" },
		"bad kind":      func(a *AAD) { a.ScopeKind = "env" },
		"no name":       func(a *AAD) { a.Name = "" },
		"dek 0":         func(a *AAD) { a.DEKVersion = 0 },
		"value 0":       func(a *AAD) { a.ValueVersion = 0 },
		"neg value ver": func(a *AAD) { a.ValueVersion = -1 },
	} {
		a := testAAD()
		f(&a)
		if _, err := Seal(dek, []byte("value"), a); err == nil {
			t.Errorf("%s: Seal accepted incomplete context", name)
		}
		if _, err := Open(dek, sealed, a); err == nil {
			t.Errorf("%s: Open accepted incomplete context", name)
		}
	}
}
