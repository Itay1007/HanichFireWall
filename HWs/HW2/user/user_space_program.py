def show_fw_state():
    pass


def reset_fw_state():
    pass


def validate_user_input(argc, argv):
    if argc == 1:
        return
    elif argc > 2:
        print("Usage: ./user_space_program [0]\nDo not add one optional reset parameter to the program")
        exit(0)

    try:
        reset_option = int(argv[1])
        if reset_option != 0:
            print("The optional argument should be set to '0'")
            exit(0)
    except TypeError as e:
        print("The optional argument should be of type int")
        print(e)
        exit(0)


def main(argc, argv):
    validate_user_input(argc, argv)

    perform_reset = argc == 2

    if perform_reset:
        reset_fw_state()
    else:
        show_fw_state()


if __name__ == "__main__":
    main()
