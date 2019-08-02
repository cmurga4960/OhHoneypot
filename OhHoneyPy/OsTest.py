from ohhoney import OhHoney

if __name__ == "__main__":

    for os in range(1484, 5651):
        print(" ~~~~~~~~~~~~~~~~~~~~~~~ test "+str(os)+" ~~~~~~~~~~~~~~~~~~~~~~~ ")
        OhHoney("eth0", str(os), "100,tcp,backdoor", "22", "/root/OhHoney/OhHoneyPy/os_tests/"+str(os)+".txt")
    print("Donezo")
