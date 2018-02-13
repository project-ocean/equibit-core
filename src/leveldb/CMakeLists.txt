# -----------------------------------------------------
# Configuration file (leveldb)
# -----------------------------------------------------

set (TARGET_NAME libleveldb)

# the target was constructed from src/Makefile.leveldb.include
set (leveldb_libleveldb_a_SOURCES
    port/atomic_pointer.h
    port/port_example.h
    port/port_posix.h
    port/win/stdint.h
    port/port.h
    port/port_win.h
    port/thread_annotations.h
    include/leveldb/db.h
    include/leveldb/options.h
    include/leveldb/comparator.h
    include/leveldb/filter_policy.h
    include/leveldb/slice.h
    include/leveldb/table_builder.h
    include/leveldb/env.h
    include/leveldb/c.h
    include/leveldb/iterator.h
    include/leveldb/cache.h
    include/leveldb/dumpfile.h
    include/leveldb/table.h
    include/leveldb/write_batch.h
    include/leveldb/status.h
    db/log_format.h
    db/memtable.h
    db/version_set.h
    db/write_batch_internal.h
    db/filename.h
    db/version_edit.h
    db/dbformat.h
    db/builder.h
    db/log_writer.h
    db/db_iter.h
    db/skiplist.h
    db/db_impl.h
    db/table_cache.h
    db/snapshot.h
    db/log_reader.h
    table/filter_block.h
    table/block_builder.h
    table/block.h
    table/two_level_iterator.h
    table/merger.h
    table/format.h
    table/iterator_wrapper.h
    util/crc32c.h
    util/arena.h
    util/random.h
    util/posix_logger.h
    util/hash.h
    util/histogram.h
    util/coding.h
    util/testutil.h
    util/mutexlock.h
    util/logging.h
    util/testharness.h

    db/builder.cc
    db/c.cc
    db/dbformat.cc
    db/db_impl.cc
    db/db_iter.cc
    db/dumpfile.cc
    db/filename.cc
    db/log_reader.cc
    db/log_writer.cc
    db/memtable.cc
    db/repair.cc
    db/table_cache.cc
    db/version_edit.cc
    db/version_set.cc
    db/write_batch.cc
    table/block_builder.cc
    table/block.cc
    table/filter_block.cc
    table/format.cc
    table/iterator.cc
    table/merger.cc
    table/table_builder.cc
    table/table.cc
    table/two_level_iterator.cc
    util/arena.cc
    util/bloom.cc
    util/cache.cc
    util/coding.cc
    util/comparator.cc
    util/crc32c.cc
    util/env.cc
    util/env_posix.cc
    util/filter_policy.cc
    util/hash.cc
    util/histogram.cc
    util/logging.cc
    util/options.cc
    util/status.cc
)

if (MSVC)
    set (leveldb_libleveldb_a_SOURCES_platform
        util/env_win.cc
        port/port_win.cc
        helpers/memenv/memenv.cc
        helpers/memenv/memenv.h
        )
else()
    set (leveldb_libleveldb_a_SOURCES_platform port/port_posix.cc)
endif()

add_library (${TARGET_NAME} STATIC ${leveldb_libleveldb_a_SOURCES} ${leveldb_libleveldb_a_SOURCES_platform})

install (TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib)

tuneup_target(${TARGET_NAME})
