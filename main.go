// You can edit this code!
// Click here and start typing.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

func main() {
	fmt.Println("Hello, 世界")
	privateKeyStr := `LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRRGNNYzJNeHd4a0xhNEYKUWx5ZmJscWc1Ny9QUUNxcHM0L2FoM3RxRGl3MWI4eHU4QVB6QmU3UkNhY2NpV0YxaXQweTZ1Vmx1MUNxUGJkRwpGaXEvRHIrb3dqbjRLdC9ZNytlL1A1QUd2UlJxR2pCT3pNK2pwRGNkTkRLZ0hNbDQvVm01MTJRNzlQWWs1d0p0CjlHNm43bE43ZmRPRStxOXJEYmJnc3BseDVpNnUyVUxnTEt0NCszd2M0TUFsMnB3VWhCNjRUdTdneG83SURuWjAKZll6ZnVLSU4xRTcwVUg2M1VnczFtd3ZQeE9OZDNZbUVIWlpSNXM3KzZnSlN4eElncHFrUGpvQnF0OUkyME40WQpkSjE3a1BtaDQxVmowMS9DUEc1d2hKdUJtZnRxYkdvQVNVRTJkRW5QT3BSUGpRb0g1WXZQSlFYUVpTbEtkNG9jCmdUODlGTE43QWdNQkFBRUNnZ0VBRXRjNEU3QUN6amVTWWtzM3ZhZS9Od3IyODhPYnlVOFI4R1lUUzBhZGtwQWsKV1lHejlNNHd3SnlOb1N2YlQxc0ZOOTlRcHltL2cvNWNySmZBS3Y1OVJWaUpINnFCNG1aMHBrcVZvS3JIZHpGNAozTElIT2o1ODF5dERBYXcwNWNtK0xPQTR6dm9nMC91Qnp1a2VHZmVTNUVnbXMrcVEzWU8xc2NVSm1DQWhqQXQvCjRYV01GSzRyMm90YVJVcmNTM2dRdTRTKytNek80RUFyVEpRbTJOeUN5ZEg4Sjc0ZWRyRW9ud2J2aDkwYzdMZ3EKS3NTRXlldXZyajFScTFEZEVwbHMyOThYVXU2TkxmYzlMWWZ1YmVWQTlYeUZuS1ZQdXVHbGtodThBTHRBejBOVQo0MFIvU1E3dldBLzZ6cU1wV3I2V3MrUGtvNEd0ZEtYTFdkT0E3K3NxZ1FLQmdRRDlJeWQ5R3JGc3I1cTdzcXpCCndWQ3ViaG1TWGpZKzNURjhZZGxjSkhwVkdKd0k1Nm9rQ2RBQjRRRTBiZlFOQjc5SDV2MmE0M2NPUU1WcERvY3UKZE1UOWxvQXJwZk9KdEYzVnRBcTY4MXBwTWtnMFcwbk9tU3grTUcxakNKV21LTStiM1IwNmYrYzhnSnNZdDhDZAoxTDJMQ1pxaERORkNUTlBlK1NTRWNlOTU0UUtCZ1FEZXIwY1J2amlCWVFCNnBFa3dwY3dFalJYa3hvcDd4TFIxClNCMitPY1FoK1l5RExtSXRQbnNBTmJTV0hoZldGcUZHU0ZPTmttT045bVZSMGJGVHAxa3RBdkpScm5VaW9Zdi8KZ0NOS09iMzhHdXJPWGhvN01vZ1gwSkQvWjRDTDdKbjN5QTlMZDYvU0dKNm9hZVJZU0F5akNPREREZWRQa3hXaQprcVJRYm9WdzJ3S0JnUUM1eG0vM3AzeG8yR09GdHZhRVoveHZWMHdiR0Z0VlBYNVEyM3JxM2JhTjl6YWtibWgyCmRHRWN6K1hUZFpKemNha1crdFpLTXYrd0RTY1VGOTVyNExTbHF5czdYVnBqU0dUSkxvM2xjQzE5SUxMUEFlUWoKNUZRNzlBeURic3h0R214cTVoYktWUTMrWUIvelB2LzBsU25aL1YxbkxvSHcxM055bzRRQ1U1Kzk0UUtCZ0NqdApWQVdKelg3UjRqR29NaDl6eVd4b3RjWm5TeHAyUzZobWliamxpd3VuZnRDNVhLZnVITk1zQzdXdmNEZ1R6cTVKCktyb1JWcVRIelZWZFVkY0xJZE9vLy9wTk14QWJXc3lwczFLNERCZmlwcGNwS204STJZUnUrOGRGTVpZRjlVSmEKRFoyVU1NZFBhUkdRN0x2ZytobVl6eDVxVnNJRVNXeW93UFJiYThFVEFvR0FDdGF0dU5ERlFvS3pnT1I2ajFGOAowdXZTd2RZYUltMDlyYVAraXNjL1JmUS9RTFBybWFpNDJSZ0lHMmhydEJRSXpnNm5LaTdWRHFxdEFVVndCZjNhCmQyQldLMk1OZDhxR211MS9qMFhHajV2V1p1VTJsbklnWlBqRkNXZTdBb3E0bHNIcnAycWF5ZEZYRWlzV2JWZmEKa0pjNGlFVHJFSnlDY1lYOFlhWHBJelk9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=`

	key := "DUWsLIp+mV+BL4QCtPGYcr2Zs0mSaqsYTn316VJHF355MrZa7u/fVgPVkFeWbJrZcePz9BeGzBqlfnB8m9C8wJZDGsO0MfAv+FZhO/EzuQ7FVrb0BtK6m9GrpW2hmqxi6P6UJ1WmTiwsh4OF4zTP2IRIvdAyO8TO7+ZNYW/bCooSIhgfonk93wB9jfG7PdqZcAs8bqQ69MMa+y1GdVNIncBwap6BmYWspyII++p4OuKc11o8AfouqtJCuDAiLWSGF//70QecYWg7w1mwXoe5M86hUY8j9tSqjfx0DQZ/khZobiGYHlGZ/zGpaRqCmQnbo24SmUq3lOR5JN70Z2bXCw=="
	keystring := getRSADecryptedString(privateKeyStr, key)
	fmt.Println(keystring)
	iv := "2I6VDXw9lYd4tSgagGRU2pa3KRvVNJHqO5K+DxZy6GGw6NRpb9wpX9mW/7Kwki+3GyAQEXUUG9JhUxZCgFMixYEzU8nypr79sRMY49OqoIkjrcsmUSFWKUPI6BAe8icI4miQxJb5QYeixvrXwhSiIoXvjibTAOLUa8xCRcEYPvt+H1FokqzFqTMRRdo3w9T8zYAiIVVpAjSLwNvyGWV4Wo7ALK9UKoCAriqx4Qq2VfkEPZXek7of3R2/Wg7aVEJkPzUYlC6/DL2jHADYgf7SkbysSHROooTRKYigKS8Y07iQx7evPQIFJAiBuLBsJWlwd4bkJZEmVpTJBTLfzv/acw=="
	eaiv := getRSADecryptedString(privateKeyStr, iv)
	fmt.Println(eaiv)

	//	sample := "iz9OJVdCn+TsL2sY+aEce4R1OilgC1TznsOAfNvI66nls7FqeSwzuF/ahCQbZFACBtLqHssmnWJG5gYgWGmE95qEG/Ttk9jBkGwBlCEjkIC0zItwuU3bPwV/i6Su2b/CaNiZ4YFnSLU7dWOo5WSB4paB0GOn5tYeqigDTQkGFKUMprPUDUsIOG7eN/ESY6cvzVPdWGzBipIrfWjdgThENH2EtTnV2/xNyHfbozNvlUoAji/2e6euBlSe2zHbf71WkaGCNzMUWzL2MScAFObSqEjt9pq+arFilgwQXtoDLWXqKGQ0vyZonFy54MZbA9BhSIvKuROuhKw36TJJ8INmHw=="
	//	sampleDecrypted:=getRSADecryptedString(privateKeyStr,sample)
	//	fmt.Println(sampleDecrypted)

	payload := "67C1320BA0B44C0575F52CDBC5033B817E5B0452BC298060262498EF436165D9F11A388DF6DEBE5AA549BC05E09360990E015D7C89A1AF0C2B67B6BB3D3461360B875B255CEC2C68F7536FA14EC6C76C41174FB4722267B501F65B5165D51922D5AFD1CAF5EE282F8297CA31DC303FBA52701C56203C67673127C25D27DFA1886694EF024BBEDEC605BC3250C480DB0065A29594878A3046B7B77A309F22D232866A45E9FA9C6A05420082E9B724D4C545F03593DA12F6D350BD1F0B54A119A382A320D264E0EA4F17680A074F66E8604681D9B2457336FC871267F765F85915B8967DA50390207D6536AAA21C2EA6E27E0F298DA0D326240772543F17FC41009E6E2EE306009CAE6516C355298B1DE7A1EC39DAEC60C8C7DFD3DDD7F907DFAA742136A67A678339FEEEB8ECF8F23EF03A6AAF6AC59932EF25270AEDF8F8F297320E54B3095A5013C07A4EA037E6A8D3520AB3CA3D440192A70701FF7CDC1C6CB914E63B320BD2B314F0F5CFB943E82ED0301269D7D35B9AF1F4CBFE9EDFF09F79A22B01A1CB89FA8E29FC082FF690584C27584CD40084D6734CA141706D2DD9EC0F409FFF6950F17331B496220A1938048610A5C3AD765F03BD0BCB70F523AEBE5D986F5B3BC98524BFB8510EA2678173B250AC4D62DEAD58A104B907C0FDEBBC1F1A700E0193C610AF66E7B9B99AFB829161A3DB0E1D36FEB61DCE636E8A65A10D35603D1B021A4A4583E6922BC3A307324C42AABE7859146E0196AC63012E1DE28D4F35038D9CBF4BDB85E45D9B2CFC3A74F68897AC88244FBAB1F89274FABB77EC475F933FE6B7D7ED4C80E228545184DD53F85AC9F89F74E877C5E8EBCBC6E1DC74A07058B8DD9197424390476105F18009358B5889F3F7F2E5126488AB"

	fmt.Println(decryptV2(payload, keystring, eaiv))

}

func decryptV2(encryptedString string, keyString string, ivString string) (string, error) {

	cipherText, err := hex.DecodeString(encryptedString)
	if err != nil {
		return "", fmt.Errorf("unable to decode hex string: [%v]", err)
	}

	// Create an AES cipher block using the provided key
	block, err := aes.NewCipher([]byte(keyString))
	if err != nil {
		return "", fmt.Errorf("error creating cipher block: [%v]", err)
	}

	// Create a CBC decrypter
	mode := cipher.NewCBCDecrypter(block, []byte(ivString))

	// Decrypt the data in-place
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)

	// Remove any padding added during encryption
	plainText = unpad(plainText)

	// Use the custom JSON decoder
	//	decryptedPayload, err := customJSONDecoder(plainText)
	//	if err != nil {
	//		return "", fmt.Errorf("error unmarshalling plainText: [%v]", err)
	//	}
	//	logger.DEBUG("decryptedPayload", tag.NewAnyTag("decryptedPayload", decryptedPayload))
	//	logger.DEBUG("plainText", tag.NewAnyTag("plainText", string(plainText)))
	//
	//	plainText, _ = jsoniter.Marshal(decryptedPayload)
	return string(plainText), nil
}

func unpad(data []byte) []byte {
	padding := data[len(data)-1]
	return data[:len(data)-int(padding)]
}

func loadRSAPrivateKey(rsaPrivateKeyPEM string) (*rsa.PrivateKey, error) {

	decodedRSAPrivateKeyPEM, err := base64.StdEncoding.DecodeString(rsaPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("error decoding private key PEM block: [%v]", err)
	}

	block, _ := pem.Decode([]byte(decodedRSAPrivateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("error decoding private key PEM block")
	}

	var rsaPrivateKey *rsa.PrivateKey
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing PKCS8 private key: [%v]", err)
		}
		var ok bool
		rsaPrivateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("error converting to RSA private key")
		}
	} else {
		return nil, fmt.Errorf("Unsupported private key type: %s", block.Type)
	}
	return rsaPrivateKey, nil
}

func getRSADecryptedString(privateKeyStr string, payload string) string {
	// Load the private key from the string
	privateKey, err := loadRSAPrivateKey(privateKeyStr)
	if err != nil {
		fmt.Println("Error loading private key:", err)
		return ""
	}

	// Example ciphertext to decrypt (replace with your actual encrypted message)
	//ciphertext := []byte(payload) // your encrypted message here

	ciphertext, _ := base64.StdEncoding.DecodeString(payload)

	fmt.Println(ciphertext)
	// Decrypt the message
	plaintext, err := DecryptRSA(privateKey, ciphertext)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return ""
	}

	// Output the decrypted message
	fmt.Println("Decrypted message:", string(plaintext))
	return string(plaintext)
}

// LoadPrivateKeyFromString loads an RSA private key from a string
func LoadPrivateKeyFromString(privateKeyStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// DecryptRSA decrypts an encrypted message using the private key
func DecryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
