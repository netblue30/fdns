#!/bin/bash

set -e

usage() {
	cat <<EOM
USAGE

    $0 [--help|--use-mock]

        --help  Show this help and exit.
        --use-mock  Build the rpm using mock.
          This requires that mock is installed and the user is allowed to use it.
EOM
}

# Basic setup
#  - Create a build dir under $TMP or /tmp as fallback.
#  - Register a trap to delete this build dir on exit.
#  - Download the source form the spec-file under $1.
#  - Copy spec-file $1 and rename it to fdns.spec.
#  - Copy all patches.
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
	if compgen -G "$(dirname "$0")"/*.patch; then
		cp "$(dirname "$0")"/*.patch "$SOURCEDIR"
	fi
}

if [ "$1" == "--help" ]; then
	usage
	exit 0
fi

# Ensure that spectool and rpmbuild are installed, if not show a helpful error.
if ! command -v spectool >/dev/null; then
	echo "Please install spectool: sudo dnf install rpmdevtools"
	exit 1
fi
if ! command -v rpmbuild >/dev/null; then
	echo "Please install rpmbuild: sudo dnf install rpm-build"
	exit 1
fi

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
			cd "$(while [[ ! -d .git && $PWD != / ]]; do cd ..; done; echo "$PWD")"
			if [[ $PWD == / ]]; then
				exit 1
			fi
			if [[ ! -e Makefile ]]; then
				./configure
			fi
			make dist
			mv fdns-*.tar.xz "$SOURCEDIR"
			cd -
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
