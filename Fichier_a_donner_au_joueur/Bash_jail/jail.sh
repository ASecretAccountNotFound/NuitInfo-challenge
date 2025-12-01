#!/bin/bash

unset PATH
enable -n exec
enable -n command
enable -n type
enable -n hash
enable -n cd
enable -n enable
set +x

echo "Only core Bash internals are allowed."
echo "The flag is hidden, and you will need to think creatively to find it!"

while true; do
    echo -n "shell> "
    if ! read user_input; then
        echo "Connection closed."
        break
    fi

    [[ -z "$user_input" ]] && continue

    case "$user_input" in 
	   *">"*|*"<"*|*"/"*|*";"*|*"&"*|*"$"*|*"("*|*"\`"*) echo "❌ Transmission blocked: Unsafe characters detected." && continue;;
    esac


    eval "$user_input"
done

