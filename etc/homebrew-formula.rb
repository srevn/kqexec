class kqexec < Formula
  desc "File and directory monitoring utility for FreeBSD and macOS"
  homepage "https://github.com/srevn/kqexec"
  url "https://github.com/srevn/kqexec/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "BSD-2-Clause"

  depends_on :macos

  def install
    system "make"
    system "make", "install", "INSTALL_PREFIX=#{prefix}"
    
    # Install documentation
    doc.install "README.md"
    
    # Create log directory with correct permissions
    (var/"log").mkpath
    touch var/"log/kqexec.log"
    touch var/"log/kqexec.err"
  end

  def caveats
    <<~EOS
      kqexec has been installed with a sample configuration file at:
        #{etc}/kqexec.conf
      
      To run kqexec as a service, use the provided launchd plist:
        sudo cp #{opt_prefix}/etc/kqexec/com.kqexec.daemon.plist /Library/LaunchDaemons/
        sudo launchctl load /Library/LaunchDaemons/com.kqexec.daemon.plist
    EOS
  end

  service do
    run [opt_bin/"kqexec", "-c", etc/"kqexec.conf"]
    keep_alive true
    log_path var/"log/kqexec.log"
    error_log_path var/"log/kqexec.err"
  end

  test do
    system "#{bin}/kqexec", "--help"
  end
end