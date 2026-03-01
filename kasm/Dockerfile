FROM kasmweb/chrome:1.16.1

USER root

ENV LAUNCH_URL=https://clawshield.example.com/control-ui/
ENV KASM_RESTRICTED_FILE_TRANSFER=DOWNLOADS
ENV KASM_SVC_AUDIO=0

# ClawShield branding — custom wallpaper + browser homepage
COPY branding/bg.svg /usr/share/backgrounds/bg.svg
COPY branding/bookmarks.html /home/kasm-user/bookmarks.html

# Set wallpaper
RUN mkdir -p /home/kasm-user/.config/xfce4/xfconf/xfce-perchannel-xml && \
    echo '<?xml version="1.0" encoding="UTF-8"?>\n\
<channel name="xfce4-desktop" version="1.0">\n\
  <property name="backdrop" type="empty">\n\
    <property name="screen0" type="empty">\n\
      <property name="monitorVNC-0" type="empty">\n\
        <property name="workspace0" type="empty">\n\
          <property name="image-style" type="int" value="5"/>\n\
          <property name="last-image" type="string" value="/usr/share/backgrounds/bg.svg"/>\n\
          <property name="color-style" type="int" value="0"/>\n\
          <property name="rgba1" type="array">\n\
            <value type="uint" value="1542"/>\n\
            <value type="uint" value="2571"/>\n\
            <value type="uint" value="6168"/>\n\
            <value type="uint" value="65535"/>\n\
          </property>\n\
        </property>\n\
      </property>\n\
    </property>\n\
  </property>\n\
</channel>' > /home/kasm-user/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml

# Chrome policies — set homepage + disable first-run
RUN mkdir -p /etc/chromium/policies/managed && \
    echo '{\n\
  "HomepageLocation": "https://clawshield.example.com/control-ui/",\n\
  "RestoreOnStartup": 4,\n\
  "RestoreOnStartupURLs": ["https://clawshield.example.com/control-ui/"],\n\
  "BookmarkBarEnabled": true,\n\
  "PasswordManagerEnabled": false,\n\
  "AutofillAddressEnabled": false,\n\
  "AutofillCreditCardEnabled": false,\n\
  "BrowserSignin": 0,\n\
  "SyncDisabled": true,\n\
  "MetricsReportingEnabled": false\n\
}' > /etc/chromium/policies/managed/clawshield.json

RUN chown -R 1000:1000 /home/kasm-user/.config

USER 1000
