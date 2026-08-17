# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_gentlsa_global_optspecs
    string join \n v/verbose json timeout= h/help V/version
end

function __fish_gentlsa_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_gentlsa_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_gentlsa_using_subcommand
    set -l cmd (__fish_gentlsa_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c gentlsa -n "__fish_gentlsa_needs_command" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_needs_command" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -s V -l version -d 'Print version'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "generate" -d 'Generate a TLSA record from a live certificate'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "list" -d 'List published TLSA records from DNS (and optionally a publisher)'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "prune" -d 'Remove stale TLSA records that no longer match the live certificate'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "rollover" -d 'Publish a new-cert hash, wait 2× the TLSA TTL, reload, wait, then prune'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "verify" -d 'Verify DNS TLSA against the live certificate (Nagios-compatible)'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "cloudflare" -d 'Cloudflare helpers'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "nsupdate" -d 'RFC 2136 / TSIG helpers'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "route53" -d 'Amazon Route 53 helpers'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "google" -d 'Google Cloud DNS helpers'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "azure" -d 'Azure DNS helpers'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "completions" -d 'Show TLSA info for a local certificate file Print a shell completion script to stdout'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "file" -d 'Mutually exclusive publisher flags shared by generate/list/prune/file/rollover'
complete -c gentlsa -n "__fish_gentlsa_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l hostname -d 'Short hostname, without the zone (for example "mx")' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l starttls -d 'STARTTLS protocol, or none for implicit TLS. Default: infer from the port (25/587 smtp, 143 imap, 110 pop3, 5222/5269 xmpp)' -r -f -a "smtp\t''
imap\t''
pop3\t''
xmpp\t''
none\t'Implicit TLS; skip STARTTLS even on ports that default to it'"
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l usage -d 'TLSA certificate usage: 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l selector -d 'TLSA selector: 0 full certificate, 1 SubjectPublicKeyInfo' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l matching -d 'TLSA matching type: 0 exact, 1 SHA2-256, 2 SHA2-512' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l info -d 'Print certificate details'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l cloudflare -d 'Publish / list / prune via the Cloudflare API'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l nsupdate -d 'Publish via RFC 2136 dynamic update (TSIG)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l route53 -d 'Publish / list / prune via Amazon Route 53'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l google -d 'Publish / list / prune via Google Cloud DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l azure -d 'Publish / list / prune via Azure DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l replace -d 'With a publisher, overwrite the existing TLSA instead of adding a rollover record'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l dryrun -d 'With a publisher, print the action but do not write records'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand generate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l hostname -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l starttls -d 'STARTTLS protocol, or none for implicit TLS. Default: infer from the port (25/587 smtp, 143 imap, 110 pop3, 5222/5269 xmpp)' -r -f -a "smtp\t''
imap\t''
pop3\t''
xmpp\t''
none\t'Implicit TLS; skip STARTTLS even on ports that default to it'"
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l cloudflare -d 'Publish / list / prune via the Cloudflare API'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l nsupdate -d 'Publish via RFC 2136 dynamic update (TSIG)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l route53 -d 'Publish / list / prune via Amazon Route 53'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l google -d 'Publish / list / prune via Google Cloud DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l azure -d 'Publish / list / prune via Azure DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l info -d 'Compare listed hashes to the live certificate'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l hostname -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l starttls -d 'STARTTLS protocol, or none for implicit TLS. Default: infer from the port (25/587 smtp, 143 imap, 110 pop3, 5222/5269 xmpp)' -r -f -a "smtp\t''
imap\t''
pop3\t''
xmpp\t''
none\t'Implicit TLS; skip STARTTLS even on ports that default to it'"
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l cloudflare -d 'Publish / list / prune via the Cloudflare API'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l nsupdate -d 'Publish via RFC 2136 dynamic update (TSIG)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l route53 -d 'Publish / list / prune via Amazon Route 53'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l google -d 'Publish / list / prune via Google Cloud DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l azure -d 'Publish / list / prune via Azure DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l dryrun
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand prune" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l hostname -d 'Short hostname, without the zone (for example "mx")' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l starttls -d 'STARTTLS protocol, or none for implicit TLS. Default: infer from the port (25/587 smtp, 143 imap, 110 pop3, 5222/5269 xmpp)' -r -f -a "smtp\t''
imap\t''
pop3\t''
xmpp\t''
none\t'Implicit TLS; skip STARTTLS even on ports that default to it'"
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l reload -d 'Command to run after 2× the TLSA TTL so the service presents the new certificate' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l ttl -d 'TLSA TTL in seconds; waits 2× this before reload and again before prune (default: 300 Cloudflare, 3600 otherwise)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l resume -d 'Resume a pending rollover after a reboot (all jobs, or one job id / zone)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l info -d 'Print certificate details'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l cloudflare -d 'Publish / list / prune via the Cloudflare API'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l nsupdate -d 'Publish via RFC 2136 dynamic update (TSIG)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l route53 -d 'Publish / list / prune via Amazon Route 53'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l google -d 'Publish / list / prune via Google Cloud DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l azure -d 'Publish / list / prune via Azure DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l dryrun -d 'Print the sequence without writing records, sleeping, or running --reload'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l schedule -d 'Write the job and start gentlsa-rollover@JOB (does not block)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand rollover" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l hostname -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l starttls -d 'STARTTLS protocol, or none for implicit TLS. Default: infer from the port (25/587 smtp, 143 imap, 110 pop3, 5222/5269 xmpp)' -r -f -a "smtp\t''
imap\t''
pop3\t''
xmpp\t''
none\t'Implicit TLS; skip STARTTLS even on ports that default to it'"
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l warn -d 'Warn when the live certificate expires in this many days or fewer' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l critical -d 'Critical when the live certificate expires in this many days or fewer' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l info
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l no-expiry-check -d 'Check the TLSA hash only, ignoring certificate expiry (pre-0.4.1 behavior)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l no-dnssec-check -d 'Skip DNSSEC validation of the TLSA records (pre-0.5.0 behavior)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand verify" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand cloudflare" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand cloudflare" -l info -d 'Print Cloudflare authentication status'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand cloudflare" -l listzones -d 'List zones available to the configured account'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand cloudflare" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand cloudflare" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand cloudflare" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand nsupdate" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand nsupdate" -l info -d 'Print nsupdate server and key (never the secret)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand nsupdate" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand nsupdate" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand nsupdate" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand route53" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand route53" -l info -d 'Print Route 53 authentication status'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand route53" -l listzones -d 'List hosted zones available to the configured account'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand route53" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand route53" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand route53" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand google" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand google" -l info -d 'Print Google Cloud DNS authentication status'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand google" -l listzones -d 'List managed zones in the configured project'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand google" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand google" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand google" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand azure" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand azure" -l info -d 'Print Azure DNS authentication status'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand azure" -l listzones -d 'List DNS zones available to the configured subscription'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand azure" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand azure" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand azure" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand completions" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand completions" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand completions" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand completions" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l zone -d 'Zone to publish into when using a publisher flag' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l hostname -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l port -d 'Service port or comma-separated list (for example 443 or 25,465)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l usage -d 'TLSA certificate usage: 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l selector -d 'TLSA selector: 0 full certificate, 1 SubjectPublicKeyInfo' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l matching -d 'TLSA matching type: 0 exact, 1 SHA2-256, 2 SHA2-512' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l timeout -d 'Overall deadline in seconds for connect, I/O, and DNS (default 30)' -r
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l info -d 'Print certificate details (on by default for this command)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l cloudflare -d 'Publish / list / prune via the Cloudflare API'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l nsupdate -d 'Publish via RFC 2136 dynamic update (TSIG)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l route53 -d 'Publish / list / prune via Amazon Route 53'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l google -d 'Publish / list / prune via Google Cloud DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l azure -d 'Publish / list / prune via Azure DNS'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l replace
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l dryrun
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -s v -l verbose -d 'Print each processing step to stderr'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -l json -d 'Emit a single JSON object on stdout instead of text'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand file" -s h -l help -d 'Print help'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "generate" -d 'Generate a TLSA record from a live certificate'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "list" -d 'List published TLSA records from DNS (and optionally a publisher)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "prune" -d 'Remove stale TLSA records that no longer match the live certificate'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "rollover" -d 'Publish a new-cert hash, wait 2× the TLSA TTL, reload, wait, then prune'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "verify" -d 'Verify DNS TLSA against the live certificate (Nagios-compatible)'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "cloudflare" -d 'Cloudflare helpers'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "nsupdate" -d 'RFC 2136 / TSIG helpers'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "route53" -d 'Amazon Route 53 helpers'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "google" -d 'Google Cloud DNS helpers'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "azure" -d 'Azure DNS helpers'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "completions" -d 'Show TLSA info for a local certificate file Print a shell completion script to stdout'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "file" -d 'Mutually exclusive publisher flags shared by generate/list/prune/file/rollover'
complete -c gentlsa -n "__fish_gentlsa_using_subcommand help; and not __fish_seen_subcommand_from generate list prune rollover verify cloudflare nsupdate route53 google azure completions file help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
