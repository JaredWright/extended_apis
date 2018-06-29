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

#include <bfvmm/memory_manager/memory_manager.h>
#include "hve/arch/intel_x64/ept/mmap.h"
// #include <intrinsics.h>
// #include <arch/intel_x64/ept/intrinsics.h>

namespace eapis
{
namespace intel_x64
{
namespace ept
{

using namespace ::intel_x64::ept;

mmap::~mmap()
{
    for (auto pml4i = 0; pml4i < ::intel_x64::ept::pml4::num_entries; pml4i++) {
        auto &entry = m_pml4.hva.at(pml4i);

        if (entry == 0) {
            continue;
        }

        this->clear_pdpt(pml4i);
    }

    this->free_page_table(m_pml4);
}

entry_type &
mmap::map_1g(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    this->map_pdpt(::intel_x64::ept::pml4::index(gpa));

    return this->map_pdpte(gpa, hpa, attr, mtype);
}

entry_type &
mmap::map_2m(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    this->map_pdpt(pml4::index(gpa));
    this->map_pd(pdpt::index(gpa));

    return this->map_pde(gpa, hpa, attr, mtype);
}

entry_type &
mmap::map_4k(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    this->map_pdpt(pml4::index(gpa));
    this->map_pd(pdpt::index(gpa));
    this->map_pt(pd::index(gpa));

    return this->map_pte(gpa, hpa, attr, mtype);
}

void
mmap::unmap(gpa_t gpa)
{
    this->map_pdpt(::intel_x64::ept::pml4::index(gpa));
    auto &pdpte = m_pdpt.hva.at(::intel_x64::ept::pdpt::index(gpa));

    if (pdpte == 0) {
        return;
    }

    if (::intel_x64::ept::pdpt::entry::entry_type::is_enabled(pdpte)) {
        pdpte = 0;
        return;
    }

    this->map_pd(::intel_x64::ept::pdpt::index(gpa));
    auto &pde = m_pd.hva.at(::intel_x64::ept::pd::index(gpa));

    if (pde == 0) {
        return;
    }

    if (::intel_x64::ept::pd::entry::entry_type::is_enabled(pde)) {
        pde = 0;
        return;
    }

    this->map_pt(::intel_x64::ept::pd::index(gpa));
    m_pt.hva.at(::intel_x64::ept::pt::index(gpa)) = 0;
}

void
mmap::release(gpa_t gpa)
{
    if (this->release_pdpte(gpa)) {
        m_pml4.hva.at(pml4::index(gpa)) = 0;
    }
}

entry_type &
mmap::gpa_to_epte(gpa_t gpa)
{
    this->map_pdpt(pml4::index(gpa));
    auto &pdpte = m_pdpt.hva.at(pdpt::index(gpa));

    if (pdpt::entry::entry_type::is_enabled(pdpte)) {
        return pdpte;
    }

    this->map_pd(pdpt::index(gpa));
    auto &pde = m_pd.hva.at(pd::index(gpa));

    if (pd::entry::entry_type::is_enabled(pde)) {
        return pde;
    }

    this->map_pt(pd::index(gpa));
    auto &pte = m_pt.hva.at(pt::index(gpa));

    return pte;
}

hpa_t
mmap::gpa_to_hpa(gpa_t gpa)
{
    this->map_pdpt(pml4::index(gpa));
    auto &pdpte = m_pdpt.hva.at(pdpt::index(gpa));

    if (pdpt::entry::entry_type::is_enabled(pdpte)) {
        return pdpt::entry::phys_addr::get(pdpte);
    }

    this->map_pd(pdpt::index(gpa));
    auto &pde = m_pd.hva.at(pd::index(gpa));

    if (pd::entry::entry_type::is_enabled(pde)) {
        return pd::entry::phys_addr::get(pde);
    }

    this->map_pt(pd::index(gpa));
    auto &pte = m_pt.hva.at(pt::index(gpa));

    return pt::entry::phys_addr::get(pte);
}

mmap::pair
mmap::allocate_page_table()
{
    auto span = gsl::make_span(
            static_cast<hva_t *>(alloc_page()),
            BAREFLANK_PAGE_SIZE / sizeof(entry_type)
        );

    mmap::pair ptrs = { span, g_mm->virtptr_to_physint(span.data()) };

    m_mdl.push_back(ptrs);
    return ptrs;
}

void
mmap::free_page_table(const mmap::pair pt_pair)
{
    for (auto iter = m_mdl.begin(); iter != m_mdl.end(); ++iter) {
        if (iter->hva == pt_pair.hva) {
            m_mdl.erase(iter);
            break;
        }
    }

    free_page(pt_pair.hva.data());
}

mmap::pair
mmap::hpa_to_pair(hpa_t hpa, size_type num_entries)
{
    auto hva = static_cast<hva_t *>(g_mm->physint_to_virtptr(hpa));

    return { gsl::make_span<hva_t>(hva, num_entries), hpa };
}

void
mmap::map_pdpt(index_type pml4i)
{
    auto &entry = m_pml4.hva.at(pml4i);

    if (entry != 0) {
        auto hpa = pml4::entry::phys_addr::get(entry);

        if (m_pdpt.hpa == hpa) {
            return;
        }

        m_pdpt = hpa_to_pair(hpa, pdpt::num_entries);
        return;
    }

    m_pdpt = this->allocate_page_table();

    pml4::entry::phys_addr::set(entry, m_pdpt.hpa);
    pml4::entry::attr_type::set(entry, attr_type::pass_through);
}

void
mmap::map_pd(index_type pdpti)
{
    auto &entry = m_pdpt.hva.at(pdpti);

    if (entry != 0) {
        auto hpa = pdpt::entry::phys_addr::get(entry);

        if (m_pd.hpa == hpa) {
            return;
        }

        m_pd = hpa_to_pair(hpa, pd::num_entries);
        return;
    }

    m_pd = this->allocate_page_table();

    pdpt::entry::phys_addr::set(entry, m_pd.hpa);
    pdpt::entry::attr_type::set(entry, attr_type::pass_through);
}

void
mmap::map_pt(index_type pdi)
{
    auto &entry = m_pd.hva.at(pdi);

    if (entry != 0) {
        auto hpa = pd::entry::phys_addr::get(entry);

        if (m_pt.hpa == hpa) {
            return;
        }

        m_pt = hpa_to_pair(hpa, pt::num_entries);
        return;
    }

    m_pt = this->allocate_page_table();

    pd::entry::phys_addr::set(entry, m_pt.hpa);
    pd::entry::attr_type::set(entry, attr_type::pass_through);
}

void
mmap::clear_pdpt(index_type pml4i)
{
    this->map_pdpt(pml4i);

    for (auto pdpti = 0; pdpti < pdpt::num_entries; pdpti++) {
        auto &entry = m_pdpt.hva.at(pdpti);

        if (entry == 0) {
            continue;
        }

        if (pdpt::entry::entry_type::is_disabled(entry)) {
            this->clear_pd(pdpti);
        }

        entry = 0;
    }

    this->free_page_table(m_pdpt);
    m_pdpt = {};
}

void
mmap::clear_pd(index_type pdpti)
{
    this->map_pd(pdpti);

    for (auto pdi = 0; pdi < pd::num_entries; pdi++) {
        auto &entry = m_pd.hva.at(pdi);

        if (entry == 0) {
            continue;
        }

        if (pd::entry::entry_type::is_disabled(entry)) {
            this->clear_pt(pdi);
        }

        entry = 0;
    }

    this->free_page_table(m_pd);
    m_pd = {};
}

void
mmap::clear_pt(index_type pdi)
{
    this->map_pt(pdi);

    this->free_page_table(m_pt);
    m_pt = {};
}

entry_type &
mmap::map_pdpte(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    auto &entry = m_pdpt.hva.at(pdpt::index(gpa));

    if (entry != 0) {
        throw std::runtime_error("map_pdpte: failed to map gpa, gpa is "
            "already mapped at the 1GB level" + bfn::to_string(gpa, 16));
    }

    pdpt::entry::phys_addr::set(entry, hpa);
    pdpt::entry::entry_type::enable(entry);
    pdpt::entry::attr_type::set(entry, attr);
    pdpt::entry::memory_type::set(entry, mtype);

    return entry;
}

entry_type &
mmap::map_pde(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    auto &entry = m_pd.hva.at(pd::index(gpa));

    if (entry != 0) {
        throw std::runtime_error("map_pde: failed to map gpa, gpa is "
            "already mapped at the 2MB level" + bfn::to_string(gpa, 16));
    }

    pd::entry::phys_addr::set(entry, hpa);
    pd::entry::entry_type::enable(entry);
    pd::entry::attr_type::set(entry, attr);
    pd::entry::memory_type::set(entry, mtype);

    return entry;
}

entry_type &
mmap::map_pte(gpa_t gpa, hpa_t hpa, attr_type attr, memory_type mtype)
{
    auto &entry = m_pt.hva.at(pt::index(gpa));

    if (entry != 0) {
        throw std::runtime_error("map_pte: failed to map gpa, gpa is "
            "already mapped at the 4KB level" + bfn::to_string(gpa, 16));
    }

    pt::entry::phys_addr::set(entry, hpa);
    pt::entry::entry_type::enable(entry);
    pt::entry::attr_type::set(entry, attr);
    pt::entry::memory_type::set(entry, mtype);

    return entry;
}

bool
mmap::release_pdpte(gpa_t gpa)
{
    this->map_pdpt(pml4::index(gpa));
    auto &entry = m_pdpt.hva.at(pdpt::index(gpa));

    if (pdpt::entry::entry_type::is_disabled(entry)) {
        if (!this->release_pde(gpa)) {
            return false;
        }
    }

    entry = 0;

    auto empty = true;
    for (auto pdpti = 0; pdpti < pdpt::num_entries; pdpti++) {
        if (m_pdpt.hva.at(pdpti) != 0) {
            empty = false;
        }
    }

    if (empty) {
        this->free_page_table(m_pdpt);
        return true;
    }

    return false;
}

bool
mmap::release_pde(gpa_t gpa)
{
    this->map_pd(pdpt::index(gpa));
    auto &entry = m_pd.hva.at(pd::index(gpa));

    if (pd::entry::entry_type::is_disabled(entry)) {
        if (!this->release_pte(gpa)) {
            return false;
        }
    }

    entry = 0;

    auto empty = true;
    for (auto pdi = 0; pdi < pd::num_entries; pdi++) {
        if (m_pd.hva.at(pdi) != 0) {
            empty = false;
        }
    }

    if (empty) {
        this->free_page_table(m_pd);
        return true;
    }

    return false;
}

bool
mmap::release_pte(gpa_t gpa)
{
    this->map_pt(pd::index(gpa));
    m_pt.hva.at(pt::index(gpa)) = 0;

    auto empty = true;
    for (auto pti = 0; pti < pt::num_entries; pti++) {
        if (m_pt.hva.at(pti) != 0) {
            empty = false;
        }
    }

    if (empty) {
        this->free_page_table(m_pt);
        return true;
    }

    return false;
}

}
}
}
