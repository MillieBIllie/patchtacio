# Using Patchtacio in your browser

`patchtacio ui` opens Patchtacio in your web browser, so you can set it up without the command
line. On Windows you can also double-click `patchtacio.exe`.

```sh
patchtacio ui                 # opens your browser
patchtacio ui --no-browser    # only prints the link (for example over remote desktop)
```

A window shows the address. **Keep it open while you use Patchtacio.** To stop, click
**Stop Patchtacio** at the top of the page, or press Ctrl+C in that window. Patchtacio also stops by
itself after an hour without use.

The page is served only to this computer, and only to the browser that opened Patchtacio's link,
so other people using this computer cannot see or change your settings. The link works once,
within 2 minutes. If the browser did not open, copy the printed link into it. If you need it
again, stop Patchtacio and start it again.

## The four steps

The **Setup** page shows how far you are, with a tick for each step done.

1. **Products.** Tick every product you run. Type in the search box to find one: names, vendors and
   former names all work, such as "FortiGate" or "Pulse". Add the **version** to also learn when its
   security updates end, for example `7.4.2` or `2019`. **Notes** are for you, such as "head office
   firewall", and appear in alerts. Click **Save products**.
2. **Alerts.** Turn on one or more channels and click **Save alert settings**:
   - **Email:** your mail server, port, encryption, user name and password, sender, and recipients.
   - **Chat channel:** Microsoft Teams (a Workflows webhook), Slack or Discord, and the webhook URL.
   - **ntfy phone app:** the topic URL (use a long random topic name), an optional access token, and
     the priority.
   - **Notification on this computer:** shown only while you are logged in.

   Passwords and URLs are kept in your computer's keychain (Credential Manager on Windows,
   Keychain on macOS, the Secret Service on Linux), never in the settings file, and never shown
   again. Leave a field empty to keep the saved value. Then click **Test all channels** and check
   that the test message arrived.
3. **Findings.** Click **Download the latest data and check again**. Patchtacio lists every entry on
   CISA's list of known exploited vulnerabilities that matches your products, newest first, and the
   end-of-life dates of the versions you gave. Open an entry to see what is affected, why it matters,
   what to do and the links. When you have dealt with one, write what you did (optional) and click
   **Mark as dealt with**: Patchtacio stops alerting and reminding you about it. You can move it back
   later.

   Many entries (Windows lists hundreds, most fixed by updates you installed long ago)? Open
   **Mark many as dealt with at once**: choose the product, keep "only those added more than 30
   days ago" unless you have checked the new ones too, say what you did, and confirm you checked
   them against the version you run. **Move all back to open** under "Dealt with" undoes it.

   At the bottom, **Data sources** shows how up to date the downloaded data is and any problem with
   the last download.
4. **Daily check.** Pick a time (or leave it empty for one between 08:00 and 08:59) and click
   **Set up the daily check**. Your computer's scheduler then checks every day and sends alerts.
   **Run it now** tests the real setup; reload the page a minute later to see how it went.

Patchtacio matches by product name and does not compare versions yet, so check each entry against
the version you run. An empty list is never an all clear: CISA's list holds only flaws known to be
exploited. If the data could not be downloaded, the Findings page says so at the top.

## Good to know

- The page never sends alerts. Only the daily check does, including when you click **Run it now**.
- The settings file is the same one the command line uses (its path is at the bottom of the Setup
  page), so you can switch between the two.
- If the file was changed elsewhere while the page was open, saving is refused and the page shows
  the file as it is now. A file with errors is never overwritten: fix or move it first.
- On a Linux server without a desktop session the keychain may not be available. Use the
  environment variables instead ([ALERTS.md](ALERTS.md)).

Design and security decisions: [decisions/0005-m5-web-ui.md](decisions/0005-m5-web-ui.md).
