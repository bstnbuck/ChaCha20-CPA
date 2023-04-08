### IMPORT ###
import numpy as np
import matplotlib.pylab as plt
from tqdm import tqdm

### SETUP ###
np.seterr(over='ignore')
bytesToProcedure = 256
# use measured and saved traces
trace_array = np.load('./automated_meassuring/data/trace_array100000_normal-32byteinp.npy')
nc_array = np.load('./automated_meassuring/data/nc_array100000_normal-32byteinp.npy')

ntraces = len(trace_array)

### OPTIMIZATION
np_argmax = np.argmax
np_argmin = np.argmin
np_max = np.max
np_min = np.min
np_zeros = np.zeros

### FUNCTIONS ###
# fast Pearson Correlation Coefficient calculation
# (c) Prof. Dr. Jungk, HS-AlbSig
def corr2_coeff(A,B):
    # Rowwise mean of input arrays & subtract from input arrays themeselves
    A_mA = A - A.mean(1)[:,None]
    B_mB = B - B.mean(1)[:,None]

    # Sum of squares across rows
    ssA = (A_mA**2).sum(1);
    ssB = (B_mB**2).sum(1);

    # Finally get corr coeff
    return np.dot(A_mA,B_mB.T)/np.sqrt(np.dot(ssA[:,None],ssB[None])) 

# hamming weight numpy compatible
def hw_np(x):
    x -= (x >> 1) & 0x5555555555555555
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
    return (x * 0x0101010101010101) >> 56

def round_part1(constant, key0, nc):
    a = (constant + key0) & 0xFFFFFFFF
    d = (nc ^ a)
    return d

def round_part2(a,b,c,d):
    # perform the modular addition from round_part1, 
    # otherwise the value only contains the key part, not the constant part
    # here the output is changed to b, because it is needed 
    # and mod addition is commutative
    a = (a + b) & 0xFFFFFFFF
    # also d changes with the XOR, so calculate it again
    d = np.bitwise_xor(d, a)

    #d1 = ((d >> 16) | (d << 16)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b = np.bitwise_xor(b, c)
    return b

def const_to_byteInt ():
    c_array = ["61707865", "3320646e", "79622d32", "6b206574"]

    # cs_long for second part
    #cs_long = []
    cs = []
    for i in c_array:
        # make big endian to little endian
        ba = bytearray.fromhex(i)
        ba.reverse()
        #cs_long.append(np.uint32(struct.unpack('<L', ba)[0]))
        # some fudging (dt: pfuschen), but it works :D
        s = "0x"+''.join(format(x, '02x') for x in ba)
        for j in range(2, 10, 2):
            # fill array byte per byte
            cs.append(int(s[j:j+2], 16))
    return cs


### ATTACK ###
cs = const_to_byteInt()

cparefsMax1 = np_zeros(bytesToProcedure) # max correlations for each byte
cparefsMin1 = np_zeros(bytesToProcedure) # min correlations for each byte

bestguessMax1 = np_zeros(16) # 128 Bit for first half of the key; put your key byte guess correlations here
bestguessMin1 = np_zeros(16) # 128 Bit for first half of the key; put your negative key byte guess correlations here

cparefsMaxX2 = np.zeros(bytesToProcedure) # max correlations for each byte
cparefsMinX2 = np.zeros(bytesToProcedure) # min correlations for each byte
cparefsMaxS2 = np.zeros(bytesToProcedure) # max correlations for each byte
cparefsMinS2 = np.zeros(bytesToProcedure) # min correlations for each byte

# 128 Bit for second half of the key; put your negative and positive key byte guess here
bestguessMaxX2 = np.zeros(16) 
bestguessMinX2 = np.zeros(16) 
bestguessMaxS2 = np.zeros(16) 
bestguessMinS2 = np.zeros(16) 

cpas1 = [0] * 16 # => get all cpas to plot
cpas2_x = [0] * 16 # => get all cpas to plot
cpas2_s = [0] * 16 # => get all cpas to plot

for bnum in tqdm(range(16), desc="Breaking 256 Bit Key"):
    
    hws = np_zeros((bytesToProcedure, ntraces))

    for i in range(ntraces):
        for kguess in range(0, bytesToProcedure):
            hws[kguess, i] =  hw_np(round_part1(cs[bnum], kguess, (nc_array[i])[bnum]))
        
    corr = corr2_coeff(hws, trace_array.transpose())

    for i in range(0, bytesToProcedure):    
        # best guess for this key-byte is the max/min argument, with his cpa
        cparefsMax1[i] = np_max(corr[i])
        cparefsMin1[i] = np_min(corr[i])
    bestguessMax1[bnum] = np_argmax(cparefsMax1)
    bestguessMin1[bnum] = np_argmin(cparefsMin1)
    
    cpas1[bnum] = corr
    
    #second part
    hws_x = np_zeros((bytesToProcedure, ntraces))
    hws_s = np_zeros((bytesToProcedure, ntraces))

    for i in range(ntraces):
        for kguess in range(0, bytesToProcedure):
            hws_x[kguess, i] =  hw_np(round_part2(cs[bnum], int(bestguessMax1[bnum]), kguess, nc_array[i, bnum]))
            hws_s[kguess, i] =  hw_np(round_part2(cs[bnum], int(bestguessMin1[bnum]), kguess, nc_array[i, bnum]))

    corr_x = corr2_coeff(hws_x, trace_array.transpose())
    corr_s = corr2_coeff(hws_s, trace_array.transpose())

    for i in range(0, bytesToProcedure):    
        # best guess for this key-byte is the max/min argument, with his cpa
        cparefsMaxX2[i] = np_max(corr_x[i])
        cparefsMinX2[i] = np_min(corr_x[i])
        cparefsMaxS2[i] = np_max(corr_s[i])
        cparefsMinS2[i] = np_min(corr_s[i])
    bestguessMaxX2[bnum] = np_argmax(cparefsMaxX2)
    bestguessMinX2[bnum] = np_argmin(cparefsMinX2)
    bestguessMaxS2[bnum] = np_argmax(cparefsMaxS2)
    bestguessMinS2[bnum] = np_argmin(cparefsMinS2)
    
    cpas2_x[bnum] = corr_x
    cpas2_s[bnum] = corr_s

    
print("Best Key Guess k0-k3 Max: ", end="")
# present the output in a more readable way
for b in bestguessMax1.astype(int): print("%02x " % b, end="")
print("\nBest Key Guess k0-k3 Min: ", end="")
for b in bestguessMin1.astype(int): print("%02x " % b, end="")


print("\n\nBest Key Guess k4-k7 MaxX: ", end="")
# present the output in a more readable way
for b in bestguessMaxX2.astype(int): print("%02x " % b, end="")
print("\nBest Key Guess k4-k7 MinX: ", end="")
for b in bestguessMinX2.astype(int): print("%02x " % b, end="")
print("\nBest Key Guess k4-k7 MaxS: ", end="")
for b in bestguessMaxS2.astype(int): print("%02x " % b, end="")
print("\nBest Key Guess k4-k7 MinS: ", end="")
for b in bestguessMinS2.astype(int): print("%02x " % b, end="")

print("\nBest Key Guess Max: ", end="")
# present the output in a more readable way
for b in bestguessMax1.astype(int): print("%02x " % b, end="")
print("\nBest Key Guess Min: ", end="")
for b in bestguessMin1.astype(int): print("%02x " % b, end="")
print("\n")

plt.figure()
plt.title(f"Correlation first 128 Bit (# traces: {ntraces})")
for cpa in cpas1:
    for i in range(256):
        plt.plot(cpa[i])
#plt.show()
plt.savefig("./automated_meassuring/figures/"+str(ntraces)+"_traces_Attack_0-128Bit.png")

plt.figure()
plt.title(f"Correlation second 128 bit (-) (# traces: {ntraces})")
for cpa in cpas2_s:
    for i in range(256):
        plt.plot(cpa[i])
#plt.show()
plt.savefig("./automated_meassuring/figures/"+str(ntraces)+"_traces_Attack_129-256Bit-.png")

plt.figure()
plt.title(f"Correlation second 128 bit (+) (# traces: {ntraces})")
for cpa in cpas2_x:
    for i in range(256):
        plt.plot(cpa[i])
#plt.show()
plt.savefig("./automated_meassuring/figures/"+str(ntraces)+"_traces_Attack_129-256Bit+.png")