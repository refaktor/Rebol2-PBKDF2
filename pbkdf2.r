REBOL []

pbkdf2: context [

 unsigned-to-binary: func [n [number!] /rev][
  if n > (2 ** 31 - 1) [n: n - (2 ** 32)]
  n: load join "#{" [form to-hex to-integer n "}"]
  either rev [head reverse n][n]
 ]

 calc-sha1: func [ pwd salt count key-len /string 
  /local hash-len block-len output i j ] [
  hash-len: length? to-string checksum/secure ""
  block-cnt: round/ceiling (key-len / hash-len)
  output: copy #{}
  repeat i block-cnt [
   last: join salt unsigned-to-binary i
   last: xorsum: checksum/key last pwd
   repeat j (count - 1) [
    xorsum: (xorsum xor (last: checksum/key last pwd))
   ]
   output: join output xorsum
  ]
  output: copy/part output key-len
  either string [ trim/with enbase/base output 16 #"^/" ] [ output ]
 ]

]