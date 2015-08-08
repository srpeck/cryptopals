/ cryptopals.com challenges, set 1
/ 1.1 Hex string to base64 string
s11a:"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
s11b:"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
hex:{"X"$0N 2#x}                                        / Hex string to hex value
xtoa:{"c"$hex x}                                        / Hex string to ASCII string
atob:{0b vs"x"$x}'                                      / ASCII string to 8 bit vector
b2tob10:{sum x*reverse 2 xexp til count x}              / Base2 to base10
bto64:{.Q.b6@"i"$b2tob10 x}'                            / 6 bit vector to base64 string
ato64:{bto64 0N 6#raze atob x}                          / ASCII string to base64 string
s11b~ato64 xtoa s11a

/ 1.2 XOR hex strings
s12a:"1c0111001f010100061a024b53535009181c"
s12b:"686974207468652062756c6c277320657965"
s12c:"746865206b696420646f6e277420706c6179"
xor:{0b sv(0b vs x)<>0b vs y}'
(hex s12c)~xor[hex s12a;hex s12b]

/ 1.3 XOR by 1 char; score by char frequency
s13:"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
cf:reverse"eEtTaAoOiInN sShHrRdDlLuUfFcCmMgGyYpPwWbBvVkKjJxXqQzZ"
xorsingle:{"c"$xor[x;]each"x"$til 128}                  / XOR with single ASCII char
score:{sum(1+til count a)*a:count each(group x)cf}      / Weighted score by char frequency
hiscore:{x a?max over a:score each x}
hiscore xorsingle hex s13

/ 1.4 Find XORed line in file
hiscore hiscore each xorsingle each hex each read0`:4.txt

/ 1.5 Repeating key XOR encryption
s15a:"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
s15b:"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
repkey:{xor["x"$y;"x"$(count y)#x]}
s15b~raze over string repkey["ICE";]each 0N 3#s15a

/ 1.6 Break repeating key XOR
f16:raze read0`:6.txt                                   / Read file as flat vector
b64tob:{"B"$''0N 8#raze over string 2_'atob .Q.b6?x}    / Base64 string to 8 bit vector
btoa:{"c"$b2tob10 x}'                                   / 8 bit vector to ASCII
b64toa:{btoa b64tob x}                                  / Base64 string to ASCII
f16v:{0N 2#(0N;x)#b64toa f16}each 2+til 39              / Reshape into vector of keyshape pairs
hamming:{sum not(raze atob x)=raze atob y}              / Convert to bits and sum difference
avgham:{(.[hamming;(x 0;x 1);0])%count x}'              / Protected execution for length errors
nhd:{sum avgham x}'                                     / Normalized hamming distance
keysize:{a?min a:nhd x}                                 / Find best keysize
raze over flip hiscore each xorsingle each "x"$flip a[;til count first a:raze f16v keysize f16v] / flip to run XOR single byte scoring on keysize strings, then reassemble by flipping back
