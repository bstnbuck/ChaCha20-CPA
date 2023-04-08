from chacha20_meassure import chacha20_meassure

#meassure_values = [(80000,1), (100000,2), (150000,2)]
meassure_values = [(8,1), (10,2), (15,2)]

for mv in meassure_values:
    if mv[1] == 1:
        print("Meassure %s traces with normal ChaCha20" % mv[0])
        chacha20_meassure(mv[0],mv[1])
    elif mv[1] == 2:
        print("Meassure %s traces with shuffled ChaCha20" % mv[0])
        chacha20_meassure(mv[0], mv[1])
    print("Done meassuring")
    