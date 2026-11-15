class Caphe < Formula
  desc "CPU-native compiled security workflow engine"
  homepage "https://github.com/andrew-ships-stuff/caphe"
  license "MIT"
  head "https://github.com/andrew-ships-stuff/caphe.git", branch: "main"

  depends_on "go@1.26" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "./cmd/caphe"
  end

  test do
    assert_match "compilerVersion", shell_output("#{bin}/caphe version")
  end
end
