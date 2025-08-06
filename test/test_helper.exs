ExUnit.configure(formatters: [ExUnit.CLIFormatter, ExUnitNotifier], exclude: [:tezos])

ExUnit.start()
