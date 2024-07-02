rule CactusRule 
{ 
 strings: 
 $cactusStr = “CaCtUs.ReAdMe.txt” 
 $cactusHex = { 43 61 43 74 55 73 2e 52 65 41 64 4d 65 2e 74 78 74 } 
 condition: 
 $cactusStr or $cactusHex 
}
