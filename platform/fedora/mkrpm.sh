#!/bin/bash

set -euo pipefail

if ! command -v spectool; then
	echo "Please install spectool: sudo dnf install rpmdevtools"
	exit 1
fi
if ! command -v rpmbuild; then
	echo "Please install rpmbuild: sudo dnf install rpm-build"
	exit 1
fi

find_repo_root() {
	local CWD="$PWD"
	while [[ ! -d .git && $PWD != / ]]; do
		cd ..
	done
	REPO_ROOT="$PWD"
	cd "$CWD"
	if [ "$REPO_ROOT" == / ]; then
		return 1
	else
		return 0
	fi
}

setup() {
	TOPDIR=$(mktemp -dt fdns-build.XXXXXX)
	SOURCEDIR=$(rpm --define "_topdir $TOPDIR" --eval %_sourcedir)
	SPECDIR=$(rpm --define "_topdir $TOPDIR" --eval %_specdir)
	BUILDDIR=$(rpm --define "_topdir $TOPDIR" --eval %_builddir)
	RPMDIR=$(rpm --define "_topdir $TOPDIR" --eval %_rpmdir)
	SRPMDIR=$(rpm --define "_topdir $TOPDIR" --eval %_srcrpmdir)

	mkdir -p "$BUILDDIR" "$RPMDIR" "$SOURCEDIR" "$SPECDIR" "$SRPMDIR"
	# shellcheck disable=SC2064
	trap "rm -rf '$TOPDIR'" EXIT

	spectool -C "$SOURCEDIR" --gf "$1"
	cp "$1" "$SPECDIR"/fdns.spec
	cp "$(dirname "$0")"/*.patch "$SOURCEDIR"
}

echo "Which version of fdns do you want to build?"
select version in local git stable help; do
	case $version in
		stable)
			setup "$(dirname "$0")"/fdns-stable.spec
			break
		;;
		git)
			setup "$(dirname "$0")"/fdns-git.spec
			break
		;;
		local)
			setup "$(dirname "$0")"/fdns-local.spec
			find_repo_root
			tar --transform "s|${REPO_ROOT#/}|.|" --exclude=".git" -czf "$SOURCEDIR/fdns.tar.gz" "$REPO_ROOT"
			break
		;;
		help)
			echo "stable: The latest stable version of fdns."
			echo "git: The master branch on github."
			echo "local: The source files in this local git clone."
		;;
	esac
done

if [ "$1" == "--use-mock" ]; then
	rpmbuild --define "_topdir $TOPDIR" -bs "$SPECDIR"/fdns.spec

	mock "$SRPMDIR"/*.rpm
else
	rpmbuild --define "_topdir $TOPDIR" -ba "$SPECDIR"/fdns.spec

	cp "$RPMDIR"/*/*.rpm "$SRPMDIR"/*.rpm .
fi
