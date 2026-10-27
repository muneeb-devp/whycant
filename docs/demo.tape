# Records docs/demo.gif with https://github.com/charmbracelet/vhs (make demo).
Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 700
Set Padding 20
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Hide
Type "export PATH=$PWD/bin:$PATH PS1='$ ' LANG=C.UTF-8 && sh docs/demo-setup.sh && clear"
Enter
Show

Type "whycant -u www-data read /srv/app/config/db.yml"
Sleep 400ms
Enter
Sleep 5s

Type "clear" Enter
Type "whycant -u deploy exec /srv/deploy.sh"
Sleep 400ms
Enter
Sleep 4s

Type "clear" Enter
Type "whycant -u www-data delete /srv/shared/report.csv"
Sleep 400ms
Enter
Sleep 5s
