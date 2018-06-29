//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef MMAP_EPT_INTEL_X64_H
#define MMAP_EPT_INTEL_X64_H

#include <vector>

#include <bfgsl.h>
#include <bfdebug.h>

#include <arch/intel_x64/ept_paging.h>
#include <bfmemory.h>
#include <bfconstants.h>
#include <bfvmm/memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{
namespace ept
{

using gpa_t = uintptr_t;
using hpa_t = uintptr_t;
using hva_t = uintptr_t;
using size_type = size_t;
using entry_type = uint64_t;
using index_type = std::ptrdiff_t;

using namespace ::intel_x64::ept;

/// EPT Memory Map
///
/// This class constructs a set of EPT extended page tables, and provides the
/// needed APIs to map guest virtual addresses to guest physical addresses.
/// For information on how extended page tables work, please see the Intel SDM.
/// This implementation attempts to map directly to the SDM text.
///
class EXPORT_EAPIS_HVE mmap
{

public:

    // @cond

    struct pair {
        gsl::span<hva_t> hva;
        hpa_t hpa;
    };

    // @endcond

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    mmap() :
        m_pml4{this->allocate_page_table()}
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mmap();

    uintptr_t hpa()
    { return m_pml4.hpa; }

    /// Map a 1GB page frame from guest physical address to host physical
    /// address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the leaf entry that performs the map
    ///
    /// @param gpa the guest physical address to map from
    /// @param hpa the host physical address to map to
    /// @param attr the map permissions
    /// @param mtype the memory type for the mapping
    ///
    entry_type &
    map_1g(gpa_t gpa, hpa_t hpa,
        attr_type attr = attr_type::pass_through,
        memory_type mtype = memory_type::write_back);

    /// Map a 2MB page frame from guest physical address to host physical
    /// address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the leaf entry that performs the map
    ///
    /// @param gpa the guest physical address to map from
    /// @param hpa the host physical address to map to
    /// @param attr the map permissions
    /// @param mtype the memory type for the mapping
    ///
    entry_type &
    map_2m(gpa_t gpa, hpa_t hpa,
        attr_type attr = attr_type::pass_through,
        memory_type mtype = memory_type::write_back);

    /// Map a 4KB page frame from guest physical address to host physical
    /// address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the leaf entry that performs the map
    ///
    /// @param gpa the guest physical address to map from
    /// @param hpa the host physical address to map to
    /// @param attr the map permissions
    /// @param mtype the memory type for the mapping
    ///
    entry_type &
    map_4k(gpa_t gpa, hpa_t hpa,
        attr_type attr = attr_type::pass_through,
        memory_type mtype = memory_type::write_back);

    /// Unmap Virtual Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the virtual address to unmap
    ///
    void unmap(gpa_t gpa);

    /// Release Virtual Address
    ///
    /// Returns any unused page tables back to the heap, releasing memory and
    /// providing a means to reconfigure the granularity of a previous mapping.
    ///
    /// @note that unmap must be run for any existing mappings, otherwise this
    ///     function has no effect.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the virtual address to unmap
    ///
    void release(gpa_t gpa);

    /// Guest physical address to leaf extended page table entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to be converted
    /// @return Returns the leaf extended page table entry that maps @param gpa
    ///
    entry_type & gpa_to_epte(gpa_t gpa);

    /// Guest physical address to host physical address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to be converted
    /// @return Returns the host physical address that @param gpa is mapped to
    ///
    hpa_t gpa_to_hpa(gpa_t gpa);

    /// Memory Descriptor List
    ///
    /// @note The returned memory descriptor list does not describe memory
    /// mapped by the extended page tables, but rather the memory used to hold
    /// the extended page tables themselves.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return List of memory descriptors that describe the page tables
    ///
    const std::vector<pair> &
    mdl() const
    { return m_mdl; }

private:

    pair allocate_page_table();
    void free_page_table(const pair pt_pair);

    pair hpa_to_pair(hpa_t hpa, size_type num_entries);

    void map_pdpt(index_type pml4i);
    void map_pd(index_type pdpti);
    void map_pt(index_type pdi);


    void clear_pdpt(index_type pml4i);
    void clear_pd(index_type pdpti);
    void clear_pt(index_type pdi);

    entry_type &
    map_pdpte(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype);

    entry_type &
    map_pde(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype);

    entry_type &
    map_pte(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype);


    bool release_pdpte(gpa_t gpa);
    bool release_pde(gpa_t gpa);
    bool release_pte(gpa_t gpa);

private:

    std::vector<pair> m_mdl;

    pair m_pml4;
    pair m_pdpt;
    pair m_pd;
    pair m_pt;

public:

    /// @cond

    mmap(mmap &&) = default;
    mmap &operator=(mmap &&) = default;

    mmap(const mmap &) = delete;
    mmap &operator=(const mmap &) = delete;

    /// @endcond
};

}
}
}

#endif
