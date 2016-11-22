#! /usr/bin/env bash

urls=(
	http://chiselapp.com/user/rkeene/repository/autoconf/doc/trunk/tcl.m4
	http://chiselapp.com/user/rkeene/repository/autoconf/doc/trunk/shobj.m4
	http://chiselapp.com/user/rkeene/repository/autoconf/doc/trunk/versionscript.m4
)

cd "$(dirname "$(which "$0")")" || exit 1

mkdir aclocal >/dev/null 2>/dev/null

files=()

for url in "${urls[@]}"; do
	file="aclocal/$(echo "${url}" | sed 's@^.*/@@')"

	curl -lsS "${url}" > "${file}.new" || exit 1
	if diff "${file}.new" "${file}" >/dev/null 2>/dev/null; then
		rm -f "${file}.new"
	else
		mv "${file}.new" "${file}"
	fi

	files=("${files[@]}" "${file}")
done

for file in "${files[@]}"; do
	cat "${file}"
done > aclocal.m4.new

if diff aclocal.m4.new aclocal.m4 >/dev/null 2>/dev/null; then
	rm -f aclocal.m4.new
else
	mv aclocal.m4.new aclocal.m4
fi
