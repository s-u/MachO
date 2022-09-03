MachO_Info <- function(file, arch) .Call(macho, path.expand(file), if (missing(arch)) NULL else arch)
