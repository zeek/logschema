#! /bin/sh
#
# Collects individual BTest coverage information and summarizes lines
# that have no coverage. Exits with status 1 if there's any missing coverage
# (other than for lines with annotations, see below), 0 if not. In the
# first case, generates a summary in COVERAGE.missing as well as printing
# it to stdout.
#
# If the version of Zeek used supports it, the coverage analysis includes
# assessments of conditionals: for them to be considered "covered", there
# needs to have been at least one execution for which the conditional
# evaluated true and one for which it evaluated false.
#
# Needs to be run from the main BTest directory.
#
# Assumes that the scripts directory has been regularized to be "<DIR>/scripts"
# or "<DIR>/analyzer", where <DIR> is the main directory of this package.
#
# You can suppress an individual line of output by annotating the line with
# a "#@ NOT-TESTED" comment, like this:
#
#	if ( rare_condition() )
#		handle_it(); #@ NOT-TESTED
#
# You can also suppress blocks of code like this:
#
#	#@ BEGIN-NOT-TESTED
#	# Not sure if this works ...
#	logic1();
#	logic2();
#	#@ END-NOT-TESTED
#
# If you have an entire function that's missing coverage, you can annotate
# its first declaration line, like this:
#
#	function rarely_done() #@ NOT-TESTED
#		{
#		...
#		}
#
# You can annotate a @if conditional as not fully tested (i.e., the test
# suite didn't cover it both being true and it being false) using either
# "#@ FALSE-NOT-TESTED" (if the false branch hasn't been covered) or
# "#@ TRUE-NOT-TESTED".
#
# Finally, you can mark a region as outside of coverage testing using
# "#@ BEGIN-SKIP-TESTING" and "#@ END-SKIP-TESTING". These should be used
# sparingly, in situations where testing may-or-may-not provide coverage
# for the region due to additional factors.
#
# If you're adding NOT-TESTED annotations, you can re-run the script directly
# (./Scripts/summarize-coverage.sh) rather than "make coverage" (which can
# take longer. However if you add BEGIN/END annotations, you'll need to
# use "make coverage" because their presence changes the line numbers in
# the script.

DIR=`(cd ..; /bin/pwd -P)`

TMP1=tmp.cov.$$.1
TMP2=tmp.cov.$$.2
TMP3=tmp.cov.$$.3

COV=COVERAGE.missing
rm -f $COV

# Figure out where to look for scripts.
if [ -d $DIR/scripts ]; then
	SCRIPTS=scripts
else
	SCRIPTS=analyzer
fi

# Look for only this package's scripts, skipping over Zeek's base scripts.
grep -h "$DIR" .tmp/script-coverage/* |

# Make the names relative to the scripts/ directory.
sed "s,\t.*$DIR/$SCRIPTS/,\t,;s,\./,,g" |

# Skip any names that come from BTests. The directory name might be
# "tests/" or it might be "testing/", so just look for the prefix.
grep -v "$DIR/test" |

# For each line, sum up its total coverage, outputting those with none.
awk '
	{
	if ( $5 ~ /@if/ )
		{
		# Move count to the end.
		count = $1
		$1 = ""
		print $0, count
		}

	else if ( $5 ~ /@else/ )
		; # Ignore these

	else
		{
		c = $1	# hold onto the count
		$1 = "#"	# nil out 1st arg. so $0 no longer includes it

		# Truncate statement descriptions to the first line. This
		# matters for things like "if ( ... ) { ... }" blocks where
		# the "{ ... }" part can vary across multiple BTest runs due
		# to conditional code.
		desc = $0
		sub(/{.*/, "{", desc)

		n[desc] += c	# use statement name + line number as key
		}
	}

END	{
	# Look for reports that cover entire function bodies.
	for ( i in n )
		{
		if ( n[i] > 0 )
			# There is coverage for this instance, no need to
			# consider further.
			continue

		nfields = split(i, fields)
		if ( fields[nfields] != "BODY" )
			# This is not a function body.
			continue

		# This is a function body that has no usage count.
		# Extract its location so we can remember to skip any
		# entries that lie within it.
		body_file = fields[2]
		nlines = split(fields[4], lines, /-/)

		if ( nlines == 1 )
			start_line = end_line = lines[0]
		else
			{
			start_line = lines[1]
			end_line = lines[2]
			}

		# Mark every line as one to skip.
		for ( j = start_line; j <= end_line; ++j )
			++skip[body_file, j]
		}

	for ( i in n )
		{
		nfields = split(i, fields)
		type = fields[nfields]
		if ( type != "BODY" )
			{
			# Extract location to see whether it has been
			# suppressed.
			body_file = fields[2]
			nlines = split(fields[4], lines, /-/)

			if ( skip[body_file, lines[1]] > 0 )
				continue

			if ( nlines == 2 && skip[body_file, lines[2]] > 0 )
				continue
			}

		print i, n[i]
		}
	}
' |

# Remove the artificial "# " we added to "nil out" argument counts above.
# Also remove the comma after the filename.
sed 's,# ,,;s/,//' |

# Sort the output so that all of the uncovered lines in a given script are
# grouped together.  Within a script, sort based on increasing line number.
sort -n -k1 -k3 >$TMP1

# Now find any annotations of untested lines.
grep -E -rn '#@.*TEST(ED|ING)' ../$SCRIPTS |

# Don't include macro source files that are generated into final files.
grep -v '\.m4\.zeek' |

# Normalize to filename, line number, annotation.
sed "s,\.\./$SCRIPTS/,,;s,:, ,g" | awk '{ print $1, $2, $NF }' >$TMP2

# Find any conditionals.
grep -rn '^[^#]*@if' ../$SCRIPTS |

# Normalize to filename and line number.
sed "s,\.\./$SCRIPTS/,,;s,:, ,g" | awk '{ print $1, $2 }' >$TMP3

# Process the combination of the actual coverage and the annotations.
awk <$TMP1 -v ANNOTATIONS=$TMP2 -v CONDITIONALS=$TMP3 '
BEGIN	{
	state = 0 # 0 = "not in a block", 1 = "in a block"
	skip_state = 0 # 0 = "not in a skip block", 1 = "in a block"

	# Do these first, since we use them to adjust lines associated
	# with conditional annotations.
	while ( (getline <CONDITIONALS) > 0 )
		++conditional_loc[$1, $2]

	while ( (getline <ANNOTATIONS) > 0 )
		{
		file = $1
		line = $2
		anno = $3

		if ( anno == "NOT-TESTED" )
			{
			if ( state == 1 )
				gripe("#@ NOT-TESTED seen inside a #@ BEGIN-NOT-TESTED block")
			++not_tested_okay[file, line]
			}

		else if ( anno == "TRUE-NOT-TESTED" )
			{
			if ( state == 1 )
				gripe("#@ TRUE-NOT-TESTED seen inside a #@ BEGIN-NOT-TESTED block")
			line = get_cond_line(file, line)
			not_fully_tested[file, line] = 1
			}

		else if ( anno == "FALSE-NOT-TESTED" )
			{
			if ( state == 1 )
				gripe("#@ FALSE-NOT-TESTED seen inside a #@ BEGIN-NOT-TESTED block")
			line = get_cond_line(file, line)
			not_fully_tested[file, line] = 0
			}

		else if ( anno == "BEGIN-NOT-TESTED" )
			{
			if ( state == 1 )
				gripe("#@ BEGIN-NOT-TESTED seen inside a #@ BEGIN-NOT-TESTED block")

			begin_line = line + 1
			block_file = file
			state = 1
			}

		else if ( anno == "END-NOT-TESTED" )
			{
			if ( state == 0 )
				gripe("#@ END-NOT-TESTED not seen inside a #@ BEGIN-NOT-TESTED block")

			if ( file != block_file )
				gripe("#@ END-NOT-TESTED seen for a different file than #@ BEGIN-NOT-TESTED block (" block_file " vs. " file ")")

			block_range[file, begin_line] = line - 1

			for ( i = begin_line; i < line; ++i )
				++not_tested_okay[file, i]

			state = 0
			}

		else if ( anno == "BEGIN-SKIP-TESTING" )
			{
			# These are okay even inside of BEGIN-NOT-TESTED
			# blocks.
			begin_skip_line = line + 1
			skip_block_file = file
			skip_state = 1
			}

		else if ( anno == "END-SKIP-TESTING" )
			{
			if ( skip_state == 0 )
				gripe("#@ END-SKIP-TESTING not seen inside a #@ BEGIN-SKIP-TESTING block")

			if ( file != skip_block_file )
				gripe("#@ END-SKIP-TESTING seen for a different file than #@ BEGIN-SKIP-TESTING block (" skip_block_file " vs. " file ")")

			for ( i = begin_skip_line; i < line; ++i )
				++skip[file, i]

			skip_state = 0
			}

		else
			gripe("unknown annotation line: " $0)
		}

	if ( state == 1 )
		gripe("unclosed #@ BEGIN-NOT-TESTED: " file ":" (begin_line - 1))
	}

	{
	file = $1
	line = $3
	count = $NF

	if ( $4 ~ /@if/ )
		{
		line = get_cond_line(file, line)
		if ( ! ((file SUBSEP line) in skip) )
			++cond_seen[file, line, count]
		next
		}

	# The coverage can sometimes generate reversed ranges, like "55-54".
	# Take the smaller.
	if ( split(line, lines, "-") == 2 )
		{
		if ( lines[2] < lines[1] )
			line = lines[2]
		else
			line = lines[1]
		}

	key = file SUBSEP line

	if ( key in skip )
		next # do not worry about coverage

	if ( count > 0 )
		++covered[file, line]

	else if ( key in not_tested_okay )
		{
		# Implicitly track that we have made use of this annotation.
		delete not_tested_okay[file, line]

		# Track that we did this deletion, in case there are multiple
		# coverage reports for the same line.
		++did_delete[file, line]
		}

	else if ( ! (key in did_delete) )
		{ # A line with no coverage.
		$NF = "" # remove trailing '0'
		print
		}
	}

END	{
	if ( length(cond_seen) > 0 )
		{ # The Zeek version knows about conditional coverage.
		for ( cl in conditional_loc )
			{
			if ( split(cl, tmp, SUBSEP) != 2 )
				gripe("bad conditional_loc: " cl)

			file = tmp[1]
			line = get_cond_line(file, tmp[2])

			key = file SUBSEP line

			if ( key in skip )
				continue
			if ( key in not_tested_okay )
				continue

			saw_true = (cl SUBSEP 1) in cond_seen
			saw_false = (cl SUBSEP 0) in cond_seen

			if ( saw_true != saw_false )
				{
				if ( ! (key in not_fully_tested) )
					print "incomplete conditional coverage: " file ":" line, (saw_true ? "FALSE" : "TRUE") "-NOT-TESTED"

				else if ( not_fully_tested[file, line] == saw_true )
					print "mismatch conditional annotation: " file ":" line, (saw_true ? "FALSE" : "TRUE") "-NOT-TESTED"
				}

			else if ( ! saw_true )
				{
				# Zeek did not see the conditional at all.
				# That can happen if it is inside another
				# (false) conditional.
				}

			else if ( key in not_fully_tested )
				print "incorrect #@ xxx-NOT-TESTED: " file ":" line
			}
		}

	for ( file_begin_line in block_range )
		{
		if ( split(file_begin_line, tmp, SUBSEP) != 2 )
			gripe("bad file_begin_line: " file_begin_line)

		file = tmp[1]
		begin_line = tmp[2]
		end_line = block_range[file, begin_line]

		seen = 0
		for ( i = begin_line; i <= end_line; ++i )
			if ( (file SUBSEP i) in covered )
				{
				seen = i
				break
				}
			else
				delete not_tested_okay[file, i]

		if ( seen )
			{
			print "annotation block " file ":" begin_line "-" end_line " did not come up as lacking coverage, starting at", seen
			# Exit at this point, otherwise we get pointwise
			# complaints, too.
			exit
			}
		}

	for ( file_line in not_tested_okay )
		{
		if ( split(file_line, tmp, SUBSEP) != 2 )
			gripe("bad file_line: " file_line)

		file = tmp[1]
		line = tmp[2]

		if ( (file SUBSEP line) in skip )
			continue

		print "incorrect #@ NOT-TESTED: " file ":" line
		}
	}

function get_cond_line(file, line)
	{
	# For multi-line conditionals, the version we infer by searching
	# the source uses the first line of the test, while the version
	# reported by Zeek uses the last.  We could just use the Zeek
	# version and not search the source separately, but for now we try
	# looking back a few lines to see if we find a match.
	while ( ! ((file SUBSEP line) in conditional_loc) )
		{
		# Search back at most 3 lines.
		if ( --line < $3 - 3 )
			break
		}

	if ( ! ((file SUBSEP line) in conditional_loc) )
		gripe("cannot find conditional for" file ":" line)

	return line
	}

function message(msg)
	{
	print msg >"/dev/stderr"
	}

function gripe(msg)
	{
	message(msg)
	exit 1
	}
' >$COV

rm $TMP1 $TMP2 $TMP3

if [ -s $COV ]; then
	cat $COV
	exit 1
else
	rm $COV
	exit 0
fi
