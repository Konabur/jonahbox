#!/bin/sh
sed -Ei 's/(blobcast.jackboxgames.com|ecast.jackboxgames.com|jackbox.tv|JACKBOX.TV)/jackbox.nations.lol/g' "$@"
