package main

func xorSli(sli1, sli2 []byte) []byte {
	var ret []byte
	for i, v := range sli1 {
		ret = append(ret, sli2[i] ^ v)
	}
	return sli2
}

func byte4toint(sli []byte) int{
	ret := int(sli[3])
	ret += int(sli[2]) * 0x100
	ret += int(sli[1]) * 0x10000
	ret += int(sli[0]) * 0x1000000
	return ret
}