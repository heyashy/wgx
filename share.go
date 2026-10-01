package main

import (
	"fmt"
	"os"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

func (a Admin) profile(name string) (string, error) {
	return a.exportPeer(name, "")
}

func (a Admin) qr(name, output string) (string, error) {
	profile, err := a.profile(name)
	if err != nil {
		return "", err
	}
	if output != "" {
		png, err := qrcode.Encode(profile, qrcode.Medium, 512)
		if err != nil {
			return "", err
		}
		if err := secureWrite(output, png); err != nil {
			return "", err
		}
		return output, nil
	}
	code, err := qrcode.New(profile, qrcode.Low)
	if err != nil {
		return "", err
	}
	return compactQR(code.Bitmap()), nil
}

func compactQR(bits [][]bool) string {
	var out strings.Builder
	for y := 0; y < len(bits); y += 2 {
		for x := range bits[y] {
			top := !bits[y][x]
			bottom := y+1 < len(bits) && !bits[y+1][x]
			switch {
			case top && bottom:
				out.WriteRune('█')
			case top:
				out.WriteRune('▀')
			case bottom:
				out.WriteRune('▄')
			default:
				out.WriteByte(' ')
			}
		}
		out.WriteByte('\n')
	}
	return strings.TrimRight(out.String(), "\n")
}

func printQR(a Admin, name, output string) error {
	if output == "-" {
		profile, err := a.profile(name)
		if err != nil {
			return err
		}
		png, err := qrcode.Encode(profile, qrcode.Medium, 512)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(png)
		return err
	}
	result, err := a.qr(name, output)
	if err != nil {
		return err
	}
	if output != "" {
		fmt.Fprintln(os.Stdout, "Saved QR image:", result)
	} else {
		fmt.Fprintln(os.Stdout, result)
	}
	return nil
}
