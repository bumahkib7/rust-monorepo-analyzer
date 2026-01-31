class Rma < Formula
  desc "Ultra-fast Rust-native code intelligence and security analyzer"
  homepage "https://github.com/bumahkib7/rust-monorepo-analyzer"
  version "0.2.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.2.0/rma-aarch64-apple-darwin.tar.gz"
      sha256 "a8cb64780ccae440c60c41808b0f866c8c8cad396d3ebdf1cd3b674aea44f4ae"
    end
    on_intel do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.2.0/rma-x86_64-apple-darwin.tar.gz"
      sha256 "fbfcf68c1f89d3ccdfdc914ebef8de5fd73aec3c03b890900966babc5460575c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.2.0/rma-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "674738ecc2cdffd230b0a9cb2cecc807662ba535024aadcd62faf5c4ee089ee7"
    end
    on_intel do
      url "https://github.com/bumahkib7/rust-monorepo-analyzer/releases/download/v0.2.0/rma-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "445677cd464688f3240f07619c82fea1e7da30140b0ca4a6e130934c51e1bbc4"
    end
  end

  def install
    bin.install "rma"
    generate_completions_from_executable(bin/"rma", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rma --version")

    # Test scanning a simple Rust file
    (testpath/"test.rs").write('fn main() { println!("hello"); }')
    output = shell_output("#{bin}/rma scan #{testpath} --format json 2>&1")
    assert_match "findings", output
  end
end
