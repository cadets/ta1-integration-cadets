#!/usr/bin/env bash

target_uuid=$1

SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
for file_info in $(find . -exec getuuid {} +);
do
    file_uuid=${file_info##* }

    if [ "$file_uuid" == "$target_uuid" ]; then
        file_name=$(echo $file_info | cut -d ":" -f 1)
        echo -n "Found "
        echo $file_name
        # act on matching files
#         echo -n "Deleting "
#         echo $file_name
#         rm -rf $file_name
    fi
done

IFS=$SAVEIFS
