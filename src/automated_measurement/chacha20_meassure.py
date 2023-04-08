import chipwhisperer as cw
import matplotlib.pylab as plt
# tqdm shows a progress bar in for loop
from tqdm import tqdm
import numpy as np
import time
import csv
from datetime import datetime
import sys
import logging
import os


def setup():
    logging.basicConfig(filename='chacha20-meassure.log', format='%(asctime)s %(name)s %(levelname)s %(message)s', encoding='utf-8', level=logging.INFO, force=True)
    if not os.path.exists("./data"):
        os.makedirs("./data")
        logging.info("Created folder \"./data\"")
    if not os.path.exists("./figures"):
        os.makedirs("./figures")
        logging.info("Created folder \"./figures\"")

def chacha20_meassure(ntraces, mode, debug=False):
    setup()

    logging.info("\nntraces: " + str(ntraces))
    logging.info("mode:"+ str(mode))
    logging.info("debug:" + str(debug))

    scope = cw.scope()
    target = cw.target(scope, cw.targets.SimpleSerial)

    # This is important to setup the clock for the target
    scope.default_setup()

    if mode == 1:
        # Normal ChaCha20
        logging.info("Change mode to normal ChaCha20 implementation")
        print("Change mode to normal ChaCha20 implementation")
        cw.program_target(scope, cw.programmers.STM32FProgrammer, "../../../../hardware/victims/firmware/IACM-chacha20/iacm-simpleserial-chacha20-CWLITEARM.hex")
    elif mode == 2:
        # Shuffled ChaCha20
        logging.info("Change mode to shuffled ChaCha20 implementation")
        print("Change mode to shuffled ChaCha20 implementation")
        cw.program_target(scope, cw.programmers.STM32FProgrammer, "../../../../hardware/victims/firmware/IACM-chacha20-shuffled/iacm-simpleserial-chacha20-CWLITEARM.hex")
    else:
        logging.info("Continue with previous mode")
        print("Continue with previous mode")

    trace_array = []
    nc_array = []

    # ChipWhisperer allows to get fixed key elements and random nonce elements
    ktp = cw.ktp.Basic()
    # therefore get new "nc" (nonce/counter) (nonce (96 bit, 12 byte), counter (32 bit, 4 byte) => 128 bit = 16 Byte)
    # the key is always the same => use nonce element
    _, nc = ktp.next()

    s_arm = scope.arm
    t_write = target.simpleserial_write
    t_read = target.simpleserial_read
    s_capture = scope.capture
    s_ltrace = scope.get_last_trace
    trArr_append = trace_array.append
    ncArr_append = nc_array.append
    ktp_next = ktp.next

    start_time = time.time()
    for i in tqdm(range(ntraces), desc="Capturing "+str(ntraces)+" traces", unit=" traces"):
        s_arm()
        # write the generated nc element to target hardware
        t_write('p', nc, end='\n')

        ret = s_capture()
        if ret:
            logging.warning("Timeout happened during acquisition")

        # get encrypted => will not be used
        encrypted = t_read('r', 64)
        
        # fill the trace and nonce/counter array with current values
        trArr_append(s_ltrace())
        ncArr_append(nc)
        
        # generate new nonce/counter
        _, nc = ktp_next()

    logging.info("Finished meassuring")
    print("Finished meassuring")
    # convert the arrays to better performance numpy arrays
    trace_array = np.array(trace_array)
    nc_array = np.array(nc_array)
    meassure_time = time.time() - start_time

    meassure_data = [datetime.now(), ntraces, meassure_time, ntraces/meassure_time, mode]
    if not debug:
        with open("meassure_info.csv", 'a') as file:
            writer = csv.writer(file)
            writer.writerow(meassure_data)

    if not debug:
        # additionally save the arrays as files
        logging.info("Save traces to file")
        print("Save traces to file")
        np.save('data/trace_array'+str(ntraces)+'_'+str(mode)+'-32byteinp.npy', trace_array)
        np.save('data/nc_array'+str(ntraces)+'_'+str(mode)+'-32byteinp.npy', nc_array)

    logging.info("Create figure")
    print("Create figure")
    plt.figure()
    plt.title(f"Captured traces: {ntraces}")
    # plot each trace in array
    for i in range(ntraces):
        plt.plot(trace_array[i])
    if not debug:
        plt.savefig("./figures/"+str(ntraces)+"_traces_"+str(mode)+".png")

    logging.info("Dissconnect device")
    print("Dissconnect device")
    try:
        scope.dis()
        target.dis()
    except:
        pass

    logging.info("Done!")
    print("Done!")
        


if __name__== "__main__":
    mode = None
    try:
        ntraces = int(sys.argv[1])
        print("traces:", sys.argv[1])
    except:
        ntraces = 5000
    try:
        print("mode:", sys.argv[2])
        if sys.argv[2] == "1":
            print("Mode: normal")
            mode = 1
        elif sys.argv[2] == "2":
            print("Mode: shuffled")
            mode = 2
    except:
        print("No mode selected!")
        mode = 0
    try:
        print("debug:", sys.argv[3])
        if str(sys.argv[3]).lower() == "true":
            debug = True
            print("debug: True")
        else:
            debug = False
            print("debug: False")
    except:
        debug = False

    chacha20_meassure(ntraces=ntraces, mode=mode, debug=debug)
