def cli(com, display, prnt):
    while True:
        if not prnt.empty():
            while not prnt.empty():
                print(prnt.get())
        a = input("zadaj daco: ")
        if a == "con":
            b = input("zadaj adresu: ")
            c = input("zadaj port (ak prazdne tak default): ")
            if c == "":
                c = 9999
            c = int(c)
            com.put([a, [b, c]])
        elif a == "send":
            com.put([a, ["", "", ""]])
            while display.empty():
                pass
            key_list = display.get()
            for i in key_list:
                v = "no"
                if key_list[i][1] != "no" or key_list[i][1] != "sent":
                    v = "yes"
                print(f"{key_list[i][0]}: {i} | encryption: {v}")
            b = int(input("zadaj cislo mena(0-n): "))
            c = input("zadaj spravu: ")
            d = input("sifrovat spravu (0-nie, 1-ano): ")
            com.put([a, [b, c, d]])
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
            for i in dict:
                v = "no"
                if dict[i][3] != "no" or key_list[i][1] != "sent":
                    v = "yes"
                print(f"{key_list[i][0]}: {i} | encryption: {v}")
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
