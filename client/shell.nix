{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
	  buildInputs = [ pkgs.postgresql ];
	  shellHook = ''
		    export PGDATA="$PWD/postgres-data"
		    if [ ! -d "$PGDATA" ]; then
		      echo "Initializing PostgreSQL database..."
		      initdb -D "$PGDATA"
		    fi
		    pg_ctl -D "$PGDATA" -l "$PGDATA/logfile" start
		    trap "pg_ctl -D $PGDATA stop" EXIT
		  '';
}
