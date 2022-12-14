defmodule Tezex.MixProject do
  use Mix.Project

  @version "0.1.0"
  @url_docs "http://hexdocs.pm/tezex"
  @url_github "https://github.com/objkt-com/tezex"

  def project do
    [
      app: :tezex,
      version: @version,
      elixir: "~> 1.13",
      description: description(),
      package: package(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "test.watch": :test
      ],
      docs: [
        source_ref: "v#{@version}",
        source_url: @url_github,
        main: "readme",
        extras: ["README.md"]
      ],
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ]
    ]
  end

  defp description() do
    "A collection of utils to work with the Tezos blockchain using Elixir: parsing Micheline, verifying Tezos signed messages, deriving Tezos wallet addresses from public key, etc."
  end

  defp package() do
    [
      name: "tezex",
      links: %{
        "Docs" => @url_docs,
        "GitHub" => @url_github
      },
      licenses: ["MIT"],
      files: ~w(lib .formatter.exs mix.exs README* LICENSE*)
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:base_58_check, "~> 1.0"},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:enacl, "~> 1.2.1"},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:ex_unit_notifier, "~> 1.2", only: :test},
      {:excoveralls, "~> 0.15.1"},
      {:libsecp256k1, "~> 0.1.9"},
      {:mix_test_watch, "~> 1.0", only: [:dev, :test], runtime: false},
      {:starkbank_ecdsa, "~> 1.1.0"}
    ]
  end
end
