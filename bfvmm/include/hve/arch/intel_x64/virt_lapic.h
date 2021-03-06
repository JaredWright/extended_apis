//
// Bareflank Hypervisor
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

#ifndef VIRT_LAPIC_INTEL_X64_EAPIS_H
#define VIRT_LAPIC_INTEL_X64_EAPIS_H

#include <array>
#include <list>

#include "lapic_register.h"

namespace eapis
{
namespace intel_x64
{

/// Virtual LAPIC
///
/// Provides an interface to a virtual local APIC, which
/// is abstracted over both xAPIC and x2APIC functionality.
///
class EXPORT_EAPIS_HVE virt_lapic
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    virt_lapic() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    virtual ~virt_lapic() = default;

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to read
    /// @return the value of the register
    ///
    virtual uint64_t read_register(lapic_register::offset_t offset) const = 0;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to write
    /// @param val the value to write
    ///
    virtual void write_register(
        lapic_register::offset_t offset, uint64_t val) = 0;

    /// Handle interrupt window exit
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this exit
    /// @return true iff the exit is handled
    ///
    virtual bool handle_interrupt_window_exit(gsl::not_null<vmcs_t *> vmcs) = 0;

    /// Queue Interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector of the interrupt to queue
    ///
    virtual void queue_injection(uint64_t vector) = 0;

    /// Inject spurious interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the spurious vector inject
    ///
    virtual void inject_spurious(uint64_t vector) = 0;

    /// Read ID
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the ID register
    ///
    virtual uint64_t read_id() const = 0;

    /// Read version
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the version register
    ///
    virtual uint64_t read_version() const = 0;

    /// Read TPR
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the TPR
    ///
    virtual uint64_t read_tpr() const = 0;

    /// Read SVR
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the SVR
    ///
    virtual uint64_t read_svr() const = 0;

    /// Read ICR
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the ICR
    ///
    virtual uint64_t read_icr() const = 0;

    /// Write EOI
    ///
    /// @expects
    /// @ensures
    ///
    virtual void write_eoi() = 0;

    /// Write TPR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param tpr the value of the tpr to write
    ///
    virtual void write_tpr(uint64_t tpr) = 0;

    /// Write ICR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param icr the value of the ICR to write
    ///
    virtual void write_icr(uint64_t icr) = 0;

    /// Write self-IPI
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector of the self-IPI to send
    ///
    virtual void write_self_ipi(uint64_t vector) = 0;

    /// Write SVR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param svr the value of the SVR to write
    ///
    virtual void write_svr(uint64_t svr) = 0;

public:

    /// @cond

    virt_lapic(virt_lapic &&) = default;
    virt_lapic &operator=(virt_lapic &&) = default;

    virt_lapic(const virt_lapic &) = delete;
    virt_lapic &operator=(const virt_lapic &) = delete;

    /// @endcond
};

}
}

#endif
