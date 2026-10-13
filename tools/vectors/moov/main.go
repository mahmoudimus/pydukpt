// Command moovvectors computes DUKPT TDES test vectors with moov-io/dukpt.
//
// Each stdin line is "BDK KSN PIN PAN DATA" (BDK, KSN and DATA in hex). Each
// output line is the input fields followed by IPEK, current transaction key,
// ISO-0 encrypted PIN block, request and response data encryption (TDES-CBC,
// zero IV, zero padding) and request and response MAC (all hex).
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/moov-io/dukpt/pkg"
	"github.com/moov-io/dukpt/pkg/des"
)

func must(b []byte, err error) string {
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		bdk, _ := hex.DecodeString(f[0])
		ksn, _ := hex.DecodeString(f[1])
		pin, pan := f[2], f[3]
		data, _ := hex.DecodeString(f[4])
		ik, err := des.DerivationOfInitialKey(bdk, ksn)
		if err != nil {
			panic(err)
		}
		ck, err := des.DeriveCurrentTransactionKey(ik, ksn)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(w, strings.Join([]string{
			f[0], f[1], pin, pan, f[4],
			hex.EncodeToString(ik), hex.EncodeToString(ck),
			must(des.EncryptPin(ck, pin, pan, "ISO-0")),
			must(des.EncryptData(ck, nil, string(data), pkg.ActionRequest)),
			must(des.EncryptData(ck, nil, string(data), pkg.ActionResponse)),
			must(des.GenerateMac(ck, string(data), pkg.ActionRequest)),
			must(des.GenerateMac(ck, string(data), pkg.ActionResponse)),
		}, " "))
	}
}
