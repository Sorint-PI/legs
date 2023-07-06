
def start_async_interception():
    # TODO What if we receive too many packets to handle?
    # The best thing would be to save all the packets in an array and, if we start consuming more than a limited amount of memory, we start throwing errors and discarding packets.
    pass

def show_only_passwords_debug_mode():
    t = AsyncSniffer(iface="veth2",prn=lambda x: x.summary(), store=False, filter="port 389")
    t.start()

    #results = t.stop()


def show_help():
    pass

def main():
    if 'mode' == '--mode-show-only-passwords':
      pass
    
    if 'conf.interface':
      start_async_interception()

    show_help()

if __name__ == "__main__":
    main()

