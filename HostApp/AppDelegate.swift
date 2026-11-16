import AppKit

@main
@MainActor
enum DNIeTokenHostMain {
    private static var retainedDelegate: AppDelegate?

    static func main() {
        let application = NSApplication.shared
        let delegate = AppDelegate()
        retainedDelegate = delegate
        application.delegate = delegate
        application.run()
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Launching the delivery host from the documented registration command is
        // sufficient; the host owns no reader, token, certificate, or browser work.
        NSApp.terminate(nil)
    }
}
