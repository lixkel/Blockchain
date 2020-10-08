def cli(com, display, prnt):
    while True:
        if not prnt.empty():
            while not prnt.empty():
                print(prnt.get())
        a = input("zadaj daco: ")
        if a == "con":
            b = input("zadaj adresu: ")
            com.put([a, b])
        elif a == "send":
            com.put([a, ["", ""]])
            while display.empty():
                pass
            key_list = display.get()
            for i in key_list:
                print(i)
            b = int(input("zadaj cislo mena(0-n): "))
            c = input("zadaj spravu: ")
            com.put([a, [b, c]])
        elif a == "import":
            b = input("zadaj kluc: ")
            c = input("zadaj meno: ")
            com.put([a, [b, c]])
        elif a == "export":
            com.put([a, ""])
            while display.empty():
                pass
            print(display.get())
        elif a == "lsimported":
            com.put([a, ""])
            while display.empty():
                pass
            dict = display.get()
            for i in list(dict.keys()):
                print(f"{dict[i]}: {i}")
        elif a == "lsnodes":
            com.put([a, ""])
            while display.empty():
                pass
            for i in display.get():
                print(f"{i.address}: {i.authorized}")
        elif a == "start mining":
            com.put([a, ""])
        elif a == "stop mining":
            com.put([a, ""])
        elif a == "sync":
            com.put([a, ""])
            while display.empty():
                pass
            for i in display.get():
                print(f"{i.address}: {i.authorized}")
            b = int(input("zadaj cislo mena(0-n): "))
            com.put([a, b])
        elif a == "highest":
            com.put([a, ""])
        elif a == "help":
            print("\ncon\nsend\nimport\nexport\nlsimported\nlsnodes\nstart mining\nstop mining\nend\n")
        elif a == "end":
            com.put([a, ""])
            break
