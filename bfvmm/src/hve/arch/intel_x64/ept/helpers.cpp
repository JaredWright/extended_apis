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

#include <intrinsics.h>
#include "hve/arch/intel_x64/hve.h"
#include "hve/arch/intel_x64/ept/helpers.h"

namespace vmcs = ::intel_x64::vmcs;
namespace eptp = ::intel_x64::vmcs::ept_pointer;

namespace eapis
{
namespace intel_x64
{
namespace ept
{

using namespace ::intel_x64::ept;

uintptr_t align_1g(uintptr_t addr)
{ return (addr & ~(page_size_1g - 1U)); }

uintptr_t align_2m(uintptr_t addr)
{ return (addr & ~(page_size_2m - 1U)); }

uintptr_t align_4k(uintptr_t addr)
{ return (addr & ~(page_size_4k - 1U)); }

uint64_t
eptp(mmap &ept_mmap)
{
    uint64_t val = 0;
    auto pml4_hpa = ept_mmap.hpa();
    uint64_t max_page_walk_length = 3;
    if (::intel_x64::msrs::ia32_vmx_ept_vpid_cap::page_walk_length_of_4::is_enabled()) {
        max_page_walk_length = 4;
    }

    eptp::memory_type::set(val, eptp::memory_type::write_back);
    eptp::page_walk_length_minus_one::set(val, max_page_walk_length - 1);
    eptp::accessed_and_dirty_flags::disable(val);
    eptp::phys_addr::set(val, pml4_hpa);

    return val;
}

void
enable_ept(uint64_t eptp, gsl::not_null<eapis::intel_x64::hve *> hve)
{
    vmcs::ept_pointer::set(eptp);
    vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();
    hve->enable_vpid();
}

void
disable_ept(void)
{ vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable(); }

//--------------------------------------------------------------------------
// 1GB pages
//--------------------------------------------------------------------------

void
map_1g(mmap &ept_mmap, gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    auto &entry = ept_mmap.map_1g(gpa, hpa, attr, mtype);
}

void
map_n_contig_1g(mmap &ept_mmap, gpa_t gpa, hpa_t hpa, uint64_t n,
        attr_type attr, memory_type mtype)
{
    for (auto i = 0ULL; i < n; i++) {
        map_1g(ept_mmap, gpa + (i * page_size_1g), hpa + (i * page_size_1g), attr);
    }
}

void
map_range_1g(mmap &ept_mmap, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
        attr_type attr, memory_type mtype)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_1g) + 1ULL;
    map_n_contig_1g(ept_mmap, gpa_s, hpa, n, attr);
}

void
identity_map_1g(mmap &ept_mmap, gpa_t gpa, attr_type attr, memory_type mtype)
{ map_1g(ept_mmap, gpa, gpa, attr); }

void
identity_map_n_contig_1g(mmap &ept_mmap, gpa_t gpa, uint64_t n,
        attr_type attr, memory_type mtype)
{
    for (auto i = 0ULL; i < n; i++) {
        identity_map_1g(ept_mmap, gpa + (i * page_size_1g), attr);
    }
}

void
identity_map_range_1g(mmap &ept_mmap, gpa_t gpa_s, gpa_t gpa_e,
        attr_type attr, memory_type mtype)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_1g) + 1ULL;
    identity_map_n_contig_1g(ept_mmap, gpa_s, n, attr);
}

//--------------------------------------------------------------------------
// 2MB pages
//--------------------------------------------------------------------------

void
map_2m(mmap &ept_mmap, gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    auto &entry = ept_mmap.map_2m(gpa, hpa, attr, mtype);
}

void
map_n_contig_2m(mmap &ept_mmap, gpa_t gpa, hpa_t hpa, uint64_t n,
        attr_type attr, memory_type mtype)
{
    for (auto i = 0ULL; i < n; i++) {
        map_2m(ept_mmap, gpa + (i * page_size_2m), hpa + (i * page_size_2m), attr);
    }
}

void
map_range_2m(mmap &ept_mmap, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
        attr_type attr, memory_type mtype)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_2m) + 1ULL;
    map_n_contig_2m(ept_mmap, gpa_s, hpa, n, attr);
}

void
identity_map_2m(mmap &ept_mmap, gpa_t gpa, attr_type attr, memory_type mtype)
{ map_2m(ept_mmap, gpa, gpa, attr); }

void
identity_map_n_contig_2m(mmap &ept_mmap, gpa_t gpa, uint64_t n,
        attr_type attr, memory_type mtype)
{
    for (auto i = 0ULL; i < n; i++) {
        identity_map_2m(ept_mmap, gpa + (i * page_size_2m), attr);
    }
}

void
identity_map_range_2m(mmap &ept_mmap, gpa_t gpa_s, gpa_t gpa_e,
        attr_type attr, memory_type mtype)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_2m) + 1ULL;
    identity_map_n_contig_2m(ept_mmap, gpa_s, n, attr);
}

//--------------------------------------------------------------------------
// 4KB pages
//--------------------------------------------------------------------------

void
map_4k(mmap &ept_mmap, gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    auto &entry = ept_mmap.map_4k(gpa, hpa, attr, mtype);
}

void
map_n_contig_4k(mmap &ept_mmap, gpa_t gpa, hpa_t hpa, uint64_t n,
        attr_type attr, memory_type mtype)
{
    for (auto i = 0ULL; i < n; i++) {
        map_4k(ept_mmap, gpa + (i * page_size_4k), hpa + (i * page_size_4k), attr);
    }
}

void
map_range_4k(mmap &ept_mmap, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
        attr_type attr, memory_type mtype)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_4k) + 1ULL;
    map_n_contig_4k(ept_mmap, gpa_s, hpa, n, attr);
}

void
identity_map_4k(mmap &ept_mmap, gpa_t gpa, attr_type attr, memory_type mtype)
{ map_4k(ept_mmap, gpa, gpa, attr); }

void
identity_map_n_contig_4k(mmap &ept_mmap, gpa_t gpa, uint64_t n,
        attr_type attr, memory_type mtype)
{
    for (auto i = 0ULL; i < n; i++) {
        identity_map_4k(ept_mmap, gpa + (i * page_size_4k), attr);
    }
}

void
identity_map_range_4k(mmap &ept_mmap, gpa_t gpa_s, gpa_t gpa_e,
        attr_type attr, memory_type mtype)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_4k) + 1ULL;
    identity_map_n_contig_4k(ept_mmap, gpa_s, n, attr);
}

void
identity_map_bestfit_lo(ept::mmap &emm, uintptr_t gpa_s, uintptr_t gpa_e,
                        attr_type attr, memory_type mtype)
{
    expects(gpa_s == align_1g(gpa_s));
    expects(gpa_s < align_4k(gpa_e));

    const auto end_1g = align_1g(gpa_e);
    const auto end_2m = align_2m(gpa_e);
    const auto end_4k = align_4k(gpa_e);

    auto i = gpa_s;

    for (; i < end_1g; i += page_size_1g) {
        ept::identity_map_1g(emm, i, attr);
    }

    for (; i < end_2m; i += page_size_2m) {
        ept::identity_map_2m(emm, i, attr);
    }

    for (; i <= end_4k; i += page_size_4k) {
        ept::identity_map_4k(emm, i, attr);
    }
}

void
identity_map_bestfit_hi(ept::mmap &emm, uintptr_t gpa_s, uintptr_t gpa_e,
                        attr_type attr, memory_type mtype)
{
    expects(align_4k(gpa_s) == gpa_s);
    expects(align_1g(gpa_e) == gpa_e);

    const auto end_4k = align_2m(gpa_s) + page_size_2m;
    const auto end_2m = align_1g(gpa_s) + page_size_1g;
    const auto end_1g = gpa_e;

    auto i = gpa_s;

    for (; i < end_4k; i += page_size_4k) {
        ept::identity_map_4k(emm, i, attr);
    }

    for (; i < end_2m; i += page_size_2m) {
        ept::identity_map_2m(emm, i, attr);
    }

    for (; i <= end_1g; i += page_size_1g) {
        ept::identity_map_1g(emm, i, attr);
    }
}

//--------------------------------------------------------------------------
// Unmapping
//--------------------------------------------------------------------------

void
unmap(mmap &ept_mmap, gpa_t gpa)
{ ept_mmap.unmap(gpa); }

}
}
}
