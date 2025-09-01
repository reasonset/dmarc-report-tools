#!/bin/zsh
setopt null_glob
setopt extended_glob

MAIL_DIR="$1"
DEST_DIR="$2"

if ! [[ -d "$MAIL_DIR" && -d "$DEST_DIR" ]]
then
  print "extract-dmarc-xmls.zsh <source_mail_dir> <dest_extract_dir>" >&2
  exit 1
fi

for i in "$MAIL_DIR"/*(.)
do
  ripmime -i "$i" -d "$DEST_DIR" || exit 2
done

(
  cd "$DEST_DIR"
  integer count=1
  for i in *(.)
  do
    unar -r $i
    for j in */**/*.xml
    do
      if [[ -e ${j:t} ]]
      then
        mv "$j" "${j:t%.xml}-_-$(( count++ )).xml"
      else
        mv "$j" .
      fi
    done
  done

  for j in *.xml_<->
  do
    [[ "$j" = (#b)*(.xml(_<->)) ]]
    mv "$j" "${j/.xml_<->/${match[2]}.xml}"
  done

  rm -r (^(*.xml))
)