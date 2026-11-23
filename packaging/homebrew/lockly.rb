# Template for Formula/lockly.rb in fullstackspectrum/homebrew-lockly.
# The release workflow renders it with packaging/homebrew/render_formula.py,
# which fills in the sdist url and sha256 from PyPI. Lockly has no runtime
# dependencies, so there are no resource blocks. Edit everything else here
# rather than in the tap.
class Lockly < Formula
  include Language::Python::Virtualenv

  desc "Explain lockfile changes and flag the ones that deserve a review"
  homepage "https://github.com/fullstackspectrum/lockly"
  url "@URL@"
  sha256 "@SHA256@"
  license "Apache-2.0"

  depends_on "python@3.14"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/lockly --version")
    (testpath/"old/Cargo.lock").write <<~TOML
      version = 4
      [[package]]
      name = "serde"
      version = "1.0.210"
      source = "registry+https://github.com/rust-lang/crates.io-index"
    TOML
    (testpath/"Cargo.lock").write (testpath/"old/Cargo.lock").read.sub("1.0.210", "1.0.211")
    output = shell_output("#{bin}/lockly diff #{testpath}/old/Cargo.lock #{testpath}/Cargo.lock --offline --no-color")
    assert_match "1 upgraded", output
  end
end
