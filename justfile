_default:
  @just --list -u

fmt:
  cargo fmt
  tombi fmt

lint:
  cargo lint
  tombi lint
