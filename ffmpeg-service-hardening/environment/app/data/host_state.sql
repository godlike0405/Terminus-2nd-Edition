-- Host-state inventory for the transcode workstation.
--
-- packages : dpkg-tracked packages and their installed Debian version strings.
-- binaries : executables on PATH and the package that owns each one (NULL when
--            the file is not owned by any dpkg package, e.g. a local build).
-- services : systemd units and the executable each unit runs.

CREATE TABLE packages (
    name       TEXT PRIMARY KEY,
    version    TEXT NOT NULL,
    ecosystem  TEXT NOT NULL
);

CREATE TABLE binaries (
    path     TEXT PRIMARY KEY,
    package  TEXT
);

CREATE TABLE services (
    unit       TEXT PRIMARY KEY,
    exec_path  TEXT NOT NULL,
    enabled    INTEGER NOT NULL
);

INSERT INTO packages (name, version, ecosystem) VALUES
    ('ffmpeg',        '7:5.1.4-0+deb12u1', 'Debian'),
    ('ffmpeg-legacy', '7:4.4.4-0+deb11u1', 'Debian'),
    ('nginx',         '1.22.1-9',          'Debian');

INSERT INTO binaries (path, package) VALUES
    ('/usr/bin/ffmpeg',        'ffmpeg'),
    ('/usr/bin/ffprobe',       'ffmpeg'),
    ('/opt/legacy/bin/ffmpeg', 'ffmpeg-legacy'),
    ('/usr/local/bin/ffmpeg',  NULL),
    ('/usr/sbin/nginx',        'nginx');

INSERT INTO services (unit, exec_path, enabled) VALUES
    ('transcode@.service',        '/usr/bin/ffmpeg',        1),
    ('thumbnailer.service',       '/usr/bin/ffprobe',       1),
    ('archive-transcode.service', '/opt/legacy/bin/ffmpeg', 0),
    ('preview.service',           '/usr/local/bin/ffmpeg',  1),
    ('edge-router.service',       '/usr/sbin/nginx',        1);
