/* 
 * This file was machine generated for 
 *  draft-ietf-nfsv4-pnfs-block-07 
 * Last updated Tue Apr 1 15:57:06 EST 2008 
 */ 
/* 
 *  Copyright (C) The IETF Trust (2007-2008) 
 *  All Rights Reserved. 
 * 
 *  Copyright (C) The Internet Society (1998-2006). 
 *  All Rights Reserved. 
 */ 
 
/* 
 *      nfs4_block_layout_prot.x 
 */ 
 
%#include "nfsv41.h" 
 
/* From NFS4.1 */
typedef unsigned int		uint32_t;
typedef hyper		int64_t;
typedef unsigned hyper	uint64_t;

const NFS4_DEVICEID4_SIZE = 16;

typedef opaque  deviceid4[NFS4_DEVICEID4_SIZE];
typedef uint64_t	length4;
typedef uint64_t	offset4;
/* End from NFS4.1 */

struct pnfs_block_sig_component4 {  /* disk signature component */ 
    int64_t bsc_sig_offset;         /* byte offset of component 
                                       on volume*/ 
    opaque  bsc_contents<>;         /* contents of this component 
                                       of the signature */ 
}; 
 
enum pnfs_block_volume_type4 { 
    PNFS_BLOCK_VOLUME_SIMPLE = 0,   /* volume maps to a single 
                                       LU */ 
    PNFS_BLOCK_VOLUME_SLICE  = 1,   /* volume is a slice of 
                                       another volume */  
    PNFS_BLOCK_VOLUME_CONCAT = 2,   /* volume is a 
                                       concatenation of 
                                       multiple volumes */ 
    PNFS_BLOCK_VOLUME_STRIPE = 3    /* volume is striped across 
                                       multiple volumes */ 
}; 
 
const PNFS_BLOCK_MAX_SIG_COMP = 16; /* maximum components per 
                                       signature */ 
struct pnfs_block_simple_volume_info4 { 
    pnfs_block_sig_component4 bsv_ds<PNFS_BLOCK_MAX_SIG_COMP>;  
                                    /* disk signature */ 
}; 
 
 
struct pnfs_block_slice_volume_info4 { 
    offset4  bsv_start;             /* offset of the start of the 
                                       slice in bytes */ 
    length4  bsv_length;            /* length of slice in bytes */ 
    uint32_t bsv_volume;            /* array index of sliced 
                                       volume */ 
}; 
 
struct pnfs_block_concat_volume_info4 { 
    uint32_t  bcv_volumes<>;        /* array indices of volumes  
                                       which are concatenated */ 
}; 
 
struct pnfs_block_stripe_volume_info4 { 
    length4  bsv_stripe_unit;       /* size of stripe in bytes */ 
    uint32_t bsv_volumes<>;         /* array indices of volumes  
                                       which are striped across -- 
                                       MUST be same size */ 
}; 
 
union pnfs_block_volume4 switch (pnfs_block_volume_type4 type) { 
    case PNFS_BLOCK_VOLUME_SIMPLE: 
        pnfs_block_simple_volume_info4  bv_simple_info; 
    case PNFS_BLOCK_VOLUME_SLICE: 
        pnfs_block_slice_volume_info4 bv_slice_info; 
    case PNFS_BLOCK_VOLUME_CONCAT: 
        pnfs_block_concat_volume_info4 bv_concat_info; 
    case PNFS_BLOCK_VOLUME_STRIPE: 
        pnfs_block_stripe_volume_info4 bv_stripe_info; 
}; 
 
/* block layout specific type for da_addr_body */ 
struct pnfs_block_deviceaddr4 { 
    pnfs_block_volume4 bda_volumes<>;  /* array of volumes */ 
}; 
 
enum pnfs_block_extent_state4 { 
    PNFS_BLOCK_READWRITE_DATA = 0,  /* the data located by this 
                                       extent is valid 
                                       for reading and writing. */ 
    PNFS_BLOCK_READ_DATA      = 1,  /* the data located by this 
                                       extent is valid for reading 
                                       only; it may not be 
                                       written. */ 
    PNFS_BLOCK_INVALID_DATA   = 2,  /* the location is valid; the 
                                       data is invalid.  It is a 
                                       newly (pre-) allocated 
                                       extent. There is physical 
                                       space on the volume. */ 
    PNFS_BLOCK_NONE_DATA      = 3   /* the location is invalid. It 
                                       is a hole in the file. 
                                       There is no physical space 
                                       on the volume. */ 
}; 
 
struct pnfs_block_extent4 { 
    deviceid4    bex_vol_id;        /* id of logical volume on 
                                       which extent of file is 
                                       stored. */ 
    offset4      bex_file_offset;   /* the starting byte offset in 
                                       the file */ 
    length4      bex_length;        /* the size in bytes of the 
                                       extent */ 
    offset4      bex_storage_offset;/* the starting byte offset in 
                                       the volume */ 
    pnfs_block_extent_state4 bex_state; 
                                    /* the state of this extent */ 
}; 
 
/* block layout specific type for loc_body */ 
struct pnfs_block_layout4 { 
    pnfs_block_extent4 blo_extents<>; 
                                    /* extents which make up this 
                                       layout. */ 
}; 
 
/* block layout specific type for lou_body */ 
struct pnfs_block_layoutupdate4 { 
    pnfs_block_extent4 blu_commit_list<>;  
                                    /* list of extents which 
                                     * now contain valid data. 
                                     */ 
}; 
 
/* block layout specific type for loh_body */ 
struct pnfs_block_layouthint4 { 
    uint64_t blh_maximum_io_time;   /* maximum i/o time in seconds 
                                       */ 
}; 
 
const RCA4_BLK_LAYOUT_RECALL_ANY_LAYOUTS = 4; 
