
#include <stdio.h>
#include <alt_types.h>
#include "system.h"
#include "altera_avalon_pio_regs.h"
#include <unistd.h>
#include <io.h>
#include <altera_avalon_epcs_flash_controller.h>
#include "epcs_commands.h"

// EPCS control/status register offsets
#define EPCS_RXDATA_OFFSET  (0x00>>2)
#define EPCS_TXDATA_OFFSET  (0x04>>2)
#define EPCS_STATUS_OFFSET  (0x08>>2)
#define EPCS_CONTROL_OFFSET (0x0C>>2)

// EPCS Bit Masks
#define EPCS_STATUS_TMT_MASK  0x20
#define EPCS_STATUS_TRDY_MASK 0x40
#define EPCS_STATUS_RRDY_MASK 0x80

#define EPCS_CONTROL_SSO_MASK 0x400

// EPCS commands
#define EPCS_COMMAND_READ 0x03
#define EPCS_COMMAND_RDID 0x9F
#define EPCS_COMMAND_EN4B 0xB7
#define EPCS_COMMAND_EX4B 0xE9
#define EPCS_COMMAND_WREN 0x06

// Density ID
#define EPCS_256          0x19

/* Spansion JEDEC manufacturer ID */
#define EPCS_SPANSION_ID1	0x1
#define EPCS_SPANSION_ID2	0xEF

/* Spansion enable 4 bytes address command */
#define EPCS_COMMAND_BRWR	0x17
#define EPCS_SPANSION_EXTADD	0x80

/* Univeral boot copier */
#define UNIVERSAL_HDR_MAGIC1	0x0
#define UNIVERSAL_HDR_MAGIC2	0x78737983



#define EPCS_FLASH_CONTROLLER_0_REGISTER_OFFSET 1024
#define EPCS_FLASH_REGISTER_BASE EPCS_FLASH_CONTROLLER_0_BASE+EPCS_FLASH_CONTROLLER_0_REGISTER_OFFSET

//#define EPCS_SIMULATION_TEST

#define EPCS_CONTROL_SSO_MASK 0x400

int epcs_4_bytes_mode;
int epcs_spansion_flash;
unsigned long flash_ptr;


unsigned char transfer(unsigned char tx)
{
#ifndef EPCS_SIMULATION_TEST
	// Wait until controller is ready for a TX-char, then send it.
	while(! (IORD(EPCS_FLASH_REGISTER_BASE,EPCS_STATUS_OFFSET) & EPCS_STATUS_TRDY_MASK));
    IOWR(EPCS_FLASH_REGISTER_BASE,EPCS_TXDATA_OFFSET,tx);
    // Wait until an RX-character shows-up, then get it.
    while(! (IORD(EPCS_FLASH_REGISTER_BASE,EPCS_STATUS_OFFSET) & EPCS_STATUS_RRDY_MASK));
    // Wait until an RX-character shows-up, then get it.
	return IORD(EPCS_FLASH_REGISTER_BASE, EPCS_RXDATA_OFFSET);
#else /* EPCS_SIMULATION_TEST */
	    // For simulation tests, read a byte from the address in r_flash_ptr
	    // and increment it to mimic the sequential read nature of an EPCS
	    // device. r_flash_ptr in the context of the EPCS bootloader
	    // refers to the flash offset within the EPCS device. We'll
	    // add this to any flash base specified with the preprocessor.
	    // to allow testing with a conventional parallel flash simulation model.
	    mov     rf_temp, r_zero
	#ifdef EPCS_SIMULATION_TEST_FLASH_BASE
	    movhi   rf_temp, %hi(EPCS_SIMULATION_TEST_FLASH_BASE)
	    addi    rf_temp, rf_temp, %lo(EPCS_SIMULATION_TEST_FLASH_BASE)
	#endif
	    add     r_flash_ptr, r_flash_ptr, rf_temp

	    // Read byte from the flash image & increment pointer for next time
	    ldbuio  r_read_byte_return_value, 0(r_flash_ptr)
	    addi    r_flash_ptr, r_flash_ptr, 1
#endif /* EPCS_SIMULATION_TEST */
}

unsigned long transfer4(unsigned long tx)
{
	unsigned long result;
    // clear the return value
    result =transfer((tx>>24) & 0xFF)<<24;
    result|=transfer((tx>>16) & 0xFF)<<16;
    result|=transfer((tx>>8) & 0xFF)<<8;
    result|=transfer(tx & 0xFF);
    return result;
}


void config()
{
	unsigned char value;
	    // Clear to 0
	    epcs_4_bytes_mode=0;


	    // Enable device CS via control-register bit.
	    IOWR(EPCS_FLASH_REGISTER_BASE,EPCS_CONTROL_OFFSET,EPCS_CONTROL_SSO_MASK);

	    // Read the device ID from hardware
	    transfer(EPCS_COMMAND_RDID);

	   // read 3-bytes response
	    value=transfer(0);  // read byte 0

	   /* ChinLiang: check whether is Spansion flash or not */
	   epcs_spansion_flash=0;	/* clear to zero before check */
	   epcs_spansion_flash=(EPCS_SPANSION_ID1==value) ||  (EPCS_SPANSION_ID2==value);

       value=transfer(0);          // read byte 1
       value=transfer(0);          // read byte 2 (density)

	    //disable CS
       IOWR(EPCS_FLASH_REGISTER_BASE,EPCS_CONTROL_OFFSET,0);

	   // Check the device density ID
       if(value>=EPCS_256)
       {
   	    /* Device more than 256Mbit, enable 4-bytes address mode. */
    	   epcs_4_bytes_mode=1;   /* Set 4-byte mode*/
       }
#if 0
	enable_four_bytes:

	    /* Device more than 256Mbit, enable 4-bytes address mode. */
	    movi    r_epcs_4_bytes_mode, 1   /* Set 4-byte mode*/

	    /* ChinLiang: check whether its Spansion flash or not */
	    bne     r_epcs_spansion_flash, r_zero, enable_four_bytes_spansion

	    // Enable device CS via control-register bit.
	    movi    r_eopen_eclose_tmp, EPCS_CONTROL_SSO_MASK
	    stwio   r_eopen_eclose_tmp, EPCS_CONTROL_OFFSET (r_epcs_base_address)

	    movi    r_epcs_tx_value, EPCS_COMMAND_WREN
	    nextpc  return_address_less_4
	    br      sub_tx_rx_byte_epcs

	    //disable CS
	    stwio   r_zero, EPCS_CONTROL_OFFSET (r_epcs_base_address)

	    // Enable device CS via control-register bit.
	    movi    r_eopen_eclose_tmp, EPCS_CONTROL_SSO_MASK
	    stwio   r_eopen_eclose_tmp, EPCS_CONTROL_OFFSET (r_epcs_base_address)

	    movi    r_epcs_tx_value, EPCS_COMMAND_EN4B
	    nextpc  return_address_less_4
	    br      sub_tx_rx_byte_epcs

	    //disable CS
	    stwio   r_zero, EPCS_CONTROL_OFFSET (r_epcs_base_address)
	    br      go_return

	enable_four_bytes_spansion:

	    // Enable device CS via control-register bit.
	    movi    r_eopen_eclose_tmp, EPCS_CONTROL_SSO_MASK
	    stwio   r_eopen_eclose_tmp, EPCS_CONTROL_OFFSET (r_epcs_base_address)

	    //ChinLiang: using Bank Register Write command
	    movi    r_epcs_tx_value, EPCS_COMMAND_BRWR
	    nextpc  return_address_less_4
	    br      sub_tx_rx_byte_epcs

	    //ChinLiang: with value where set EXTADD bit to 1
	    movi    r_epcs_tx_value, EPCS_SPANSION_EXTADD
	    nextpc  return_address_less_4
	    br      sub_tx_rx_byte_epcs

	    //disable CS
	    stwio   r_zero, EPCS_CONTROL_OFFSET (r_epcs_base_address)

	go_return:
	    jmp     r_riff_return_address
#endif
}

void open_address(unsigned long address)
{
	   // For RTL simulation purposes, this routine can be built to
	    // simply return
#ifdef EPCS_SIMULATION_TEST
	    // Fix-up return-address  (NOTE: LEAF)
		return;
#endif /* EPCS_SIMULATION_TEST */
	    // No fix-up, we're just a front-end

	    // Check for Device ID and enable 4-byte address mode if its density is
	    // greater than 256M bits.

	    config();

	    IOWR(EPCS_FLASH_REGISTER_BASE,EPCS_CONTROL_OFFSET,EPCS_CONTROL_SSO_MASK);
	    if(epcs_4_bytes_mode)
	    {
	    	transfer(EPCS_COMMAND_READ);
	    	transfer4(address);
	    }
	    else
	    {
	    	transfer4(EPCS_COMMAND_READ<<24 | (address & 0x00FFFFFF));
	    }
}

void close_epcs()
{
        // For RTL simulation purposes, this routine can be built to
        // simply return
#ifndef EPCS_SIMULATION_TEST
        // Wait until controller says "Transmitter empty."

	while(! (IORD(EPCS_FLASH_REGISTER_BASE,EPCS_STATUS_OFFSET) & EPCS_STATUS_TMT_MASK));

        // Deassert CS by clearing the SSO-bit (write zero to entire register):
    IOWR(EPCS_FLASH_REGISTER_BASE,EPCS_CONTROL_OFFSET,0);

/*
        // If we entered "4-byte" address mode, exit it. Other IP may expect
        // the EPCS device to be in conventioanl 3-byte address mode. We're so
        // nice here in the SCTC, thinking of these things for you.
    asm("beq     r21, r0, close_3_bytes_mode");

        // Enable device CS via control-register bit.
    asm("movi    r12, 0x400"); //EPCS_CONTROL_SSO_MASK
    asm("stwio   r12, 0x0C (r18)");

    asm("movi    r11, 0x06");//EPCS_COMMAND_WREN
    asm("nextpc  r23");
    asm("br      sub_tx_rx_byte_epcs");

        //disable CS
    asm("stwio   r0, 0x0C (r18)");

        // Enable device CS via control-register bit.
    asm("movi    r12, 0x400");//EPCS_CONTROL_SSO_MASK
    asm("stwio   r12, 0x0C (r18)");

    asm("movi    r11, 0xE9");//EPCS_COMMAND_EX4B
    asm("nextpc  r23");
    asm("br      sub_tx_rx_byte_epcs");

        //disable CS
    asm("stwio   r0, 0x0C (r18)");

    asm("close_3_bytes_mode:");

*/
#endif /* EPCS_SIMULATION_TEST */
}

unsigned long find_payload()
{
	unsigned long value,temp;
	unsigned long idx;



    flash_ptr=0;

    open_address(0);
    for(idx=0; idx<32; ++idx)
    {
        value=transfer(0);
        if(value!=0xFF)
        {
            close_epcs();
        	return 0;
        }
    }

    close_epcs();
    open_address(48);
    temp=0;

    for(idx=0; idx<25; ++idx)
    {
    	value=transfer(0);
        value=(value & 0x20)<<26;
        temp>>=1;
        temp|=value;
    }

    close_epcs();
    open_address(33);

    for(idx=0; idx<7; ++idx)
    {
    	value=transfer(0);
        value=(value & 0x10)<<27;
        temp>>=1;
        temp|=value;
    }

    temp+=7;
    temp>>=3;
    close_epcs();
    return temp;
}




unsigned long rev_long(unsigned long val)
{
	unsigned long temp, mask, idx;

	mask=0x0F0F0F0F;
	idx=4;
	do
	{
		temp=val & mask;
		temp<<=idx;
		val>>=idx;
		val &= mask;
		val |=temp;
		idx >>=1;
		temp= mask <<idx;
		mask^=temp;
	} while(idx);

	return val;
}
int main ()
{
	alt_u32 leds=0x01;
	alt_u32 jump_address=0x1800;
	alt_u32 base_address, offset;
	alt_u32 buff[32];
	alt_u32 buff2[2048];

    base_address = EPCS_FLASH_CONTROLLER_0_BASE + EPCS_FLASH_CONTROLLER_0_REGISTER_OFFSET;

//	asm ( "callr %0" ::"r"(jump_address) );
    find_payload();
    offset=(rev_long(0xdfcfefef)+7)>>3;
    offset=128533;
    //buff[0]=0x1234567;
    //epcs_write_buffer( base_address,offset,(alt_u8*)&buff,sizeof(buff),0);
    epcs_read_buffer( base_address,offset,(alt_u8*)&buff2,sizeof(buff2),0);
#if 0
	while(1)
	{
		IOWR_ALTERA_AVALON_PIO_DATA(PIO_LEDS_BASE, leds);
        leds = ((leds<<1) & 0x0E) | (!(leds>>3) & 0x1);
		usleep(50000);
	}
#endif

    asm("movi    r0,0");

//    asm ("wrctl  status, r0");
    asm ("nextpc r23");
    asm("br      sub_find_payload_epcs");
    asm("subi    r5, r0, 1");



    asm("per_record_loop:");

        // r_data_size = READ_INT(r_flash_ptr++)
    asm("nextpc  r23");
    asm("br      sub_read_int_from_flash_epcs");

    asm("mov     r3, r6");

        // r_dest = READ_INT(r_flash_ptr++)
    asm("nextpc  r23");
    asm("br      sub_read_int_from_flash_epcs");
    asm("mov     r4, r6");

        ////
        // Test to see if r_data_size (r_data_size) is r_zero.
        // When it is, we go run the program.
        //
    asm("beq     r3, r0, last_program_record");


        //   ------------------------------------------
        // | A record length of -1 (0xffffFFFF) is
        // | is a HALT record.
        // |

    asm("halt_record_forever:");
    asm("beq     r3, r5, halt_record_forever");

        // |
        //   ------------------------------------------

        // use the streaming copy routines to move the data
        //   note: if we need to save a couple of bytes, this would be a
        //          good routine to in-line.
    asm("nextpc  r23");
//        br      STREAMING_COPY

        // When you get to here, you're done with the current record.
        // And, you know that it wasn't the last one (because it's
        // length-field wasn't zero--we checked.  So, that can only mean
        // one thing.  Time for the next record:
    asm("br      per_record_loop");

    asm("last_program_record:");
        // The last Program-Record is the jump-record.  The
        // r_dest is the entry-point of the
        // program.  This is easy as cheese.
        //
        // People seem to like to "return" from their main-program, and then
        // they expet someting reasonable to happen.  Weird.


        // 2005.03.03 -- SPR 169431
        // Close the EPCS device properly before terminating the
        // boot-loader. Failing to perform this step can cause a HAL open()
        // call to open the EPCS device to fail unless a large (multi-second)
        // delay has passed.
    #ifdef EPCS
        asm("nextpc  r23");
        asm("br      sub_epcs_close");
    #endif

//        callr   r_dest

    asm("afterlife:");        // So...this is where programs go when they die.
    asm("br      afterlife");





    asm("sub_find_payload_epcs:");

    	    // Fix-up and save return-address
    asm("addi    r13, r23, 4");

    	  //
    	  // Compute the address of the EPCS control/status register block.
    	  //
    	  // This is 1024 bytes from the very *start* of this program, for this
    	  // edition of the boot loader. On Cyclone I/II its 512 bytes.
    	  //
    	  // | dvb adds: Since the code must be aligned on a 1024-byte
    	  // | boundary, we simply take our current address, and round up
    	  // | to the next 1024-byte boundary.
    	  //
    	  // | for debugging purposes, you may define EPCS_REGS_BASE
    	  // | to be the epcs registers base. Otherwise, it is presumed
    	  // | to be the first 1024-byte-boundary after this very code/
    	  //

    asm("movia 	r14,0x1878");

#ifdef EPCS_REGS_BASE
    asm("movhi   r18, %hi(EPCS_REGS_BASE)");
    asm("ori     r18, r18, %lo(EPCS_REGS_BASE)");
#else
    asm("ori     r18, r14, 1023");
    asm("addi    r18, r18, 1");
#endif

    //
    // 1) Open EPCS-device at flash-offset zero.
    //
    asm("movi    r2, 0");
    asm("nextpc  r23");
	asm("br      sub_epcs_open_address");
#if 1
	asm("movi r16,32");
	asm("movi r14,255");

	asm("check_ff_loop:");
    asm("nextpc  r23");
	asm("br      sub_read_byte_from_flash_epcs");
	asm("bne     r10, r14, fp_short_circuit");
	asm("addi r16,r16,-1");
	asm("bne r16,r0,check_ff_loop");

	asm("movi r16,25");
	asm("movi r14,0");
	asm("movi r2,48");
    asm("nextpc  r23");
    asm("br      sub_epcs_close");
    asm("nextpc  r23");
	asm("br      sub_epcs_open_address");

	asm("loop_search:");
	asm("nextpc  r23");
	asm("br      sub_read_byte_from_flash_epcs");
	asm("andi r10,r10,32");
	asm("slli r10,r10,26");
	asm("srli r14,r14,1");
	asm("or r14,r14,r10");
	asm("addi r16,r16,-1");
	asm("bne r16,r0,loop_search");

	asm("movi r16,7");
	asm("movi r2,33");
    asm("nextpc  r23");
    asm("br      sub_epcs_close");
    asm("nextpc  r23");
	asm("br      sub_epcs_open_address");

	asm("loop:");
    asm("nextpc  r23");
	asm("br      sub_read_byte_from_flash_epcs");
	asm("andi r10,r10,16");
	asm("slli r10,r10,27");
	asm("srli r14,r14,1");
	asm("or r14,r14,r10");
	asm("addi r16,r16,-1");
	asm("bne r16,zero,loop");

	asm("mov r2,r14");
	asm("movi r14,-1");
	asm("beq r2,r14,loop_0x1860");
	asm("addi r2,r2,7");
	asm("srli r2,r2,3");

    asm("fp_short_circuit:");
    // Close the EPCS device
    asm("nextpc  r23");
    asm("br      sub_epcs_close");

    // Open it up again (at r_flash_ptr)
    asm("nextpc  r23");
    asm("br      sub_epcs_open_address");

    asm("jmp     r13");


	asm("loop_0x1860:");
	asm("br loop_0x1860");

#else
    //
    // Analyze the device config by sequentially reading bytes out of the
    //  flash until one of three things happen:
    //       1) We find an 0xA6 (well, really 0x56 because we're not reversing
    //           the bits while searching).  When we find it, we've found the
    //           device configuration, and can continue figuring out it's
    //           length
    //       2) We see a byte other than 0xFF, in which case we're not looking
    //           at a device configuration at all.  Instead we assume we must
    //           be looking at a boot loader record.  Skip the whole "length
    //           of the configuration" calculation, and start loading.
    //       3) We don't find anything other than 0xFF's for an arbitrarily
    //           long time.  We then surmise that the flash must be blank, and
    //           having no other recourse, we hang.
    //

    // search an arbitrarily large number of bytes
    asm("movi    r16, 0x400");

    // the pattern we're looking for
    asm("movi    r15, 0x56");

    // what we'll accept until we see the pattern
    asm("movi    r14, 0xFF");

    asm("fp_look_for_56_loop:");
	asm("nextpc  r23");
	asm("br      sub_read_byte_from_flash_epcs");

    // did we find our pattern?
	asm("beq     r10, r15, fp_found_sync");

    // did we see something other than an FF?
	asm("bne     r10, r14, fp_short_circuit");

    // update the loop counter, and loop
	asm("subi    r16, r16, 1");
	asm("bne     r16, r0, fp_look_for_56_loop");

    // we didn't find a pattern, or anything else for that matter. Hang.
	asm("sub_epcs_hang_forever:");
	asm("br      sub_epcs_hang_forever");

    asm("fp_found_sync:");
    // The magic sync pattern is followed by four bytes we aren't interested
    //  in.  Toss 'em.
    asm("nextpc  r23");

    asm("br      sub_read_int_from_flash_epcs");

    // The next four bytes are the length of the configuration
    // They are in little-endian order, but (perversely), they
    // are each bit-reversed.
    asm("nextpc  r23");
    asm("br      sub_read_int_from_flash_epcs");

    // put length in the flash pointer
    asm("mov     r2, r6");

    // Ok, we've got the length, but in EPCS devices, Quartus stores the
    //   bytes in bit-reversed order.
    //
    //   We're going to reverse the bits by reversing nibbles, then di-bits,
    //   then bits, like this:
    //
    //  76543210 -- nibbles --> 32107654 -- di-bits --> 10325476 -- bits --> 01234567
    //
    //   Here are the machinations the following loop goes through.
    //       You'll notice that the sequence only illustrates one byte.
    //       Never fear, all of the bytes in the word are being reversed
    //       at the same time
    //
    //   ("x" == unknown, "." == zero)
    //
    //                             byte        temp        mask    count
    //                           --------    --------    --------  -----
    //   Initial state           76543210    xxxxxxxx    00001111    4
    //
    // 1 temp = byte & mask      76543210    ....3210    00001111    4
    // 2 temp <<= count          76543210    3210....    00001111    4
    // 3 byte >>= count          xxxx7654    3210....    00001111    4
    // 4 byte &= mask            ....7654    3210....    00001111    4
    // 5 byte |= temp            32107654    3210....    00001111    4
    // 6 count >>= 1             32107654    3210....    00001111    2
    // 7 temp = mask << count    32107654    00111100    00001111    2
    // 8 mask ^= temp            32107654    00111100    00110011    2
    //
    //   loop on (count != 0)
    //
    //   temp = byte & mask      32107654    ..10..54    00110011    2
    //   temp <<= count          32107654    10..54..    00110011    2
    //   byte >>= count          xx321076    10..54..    00110011    2
    //   byte &= mask            ..32..76    10..54..    00110011    2
    //   byte |= temp            10325476    10..54..    00110011    2
    //   count >>= 1             10325476    10..54..    00110011    1
    //   temp = mask << count    10325476    01100110    00110011    1
    //   mask ^= temp            10325476    01100110    01010101    1
    //
    //   loop on (count != 0)
    //
    //   temp = byte & mask      10325476    .0.2.4.6    01010101    1
    //   temp <<= count          10325476    0.2.4.6.    01010101    1
    //   byte >>= count          x1032547    0.2.4.6.    01010101    1
    //   byte &= mask            .1.3.5.7    0.2.4.6.    01010101    1
    //   byte |= temp            01234567    0.2.4.6.    01010101    1
    //   count >>= 1             01234567    0.2.4.6.    01010101    0
    //   temp = mask << count    01234567    01010101    01010101    0
    //   mask ^= temp            01234567    01010101    00000000    0
    //

    // initialize the mask
    asm("movhi   r17, 0x0F0F");
    asm("addi    r17, r17, 0x0F0F");

    // load the count
    asm("movi    r16, 4");

    asm("fp_reverse_loop:");
    // mask off half of the bits, and put the result in TEMP
    asm("and     r14, r2, r17");       // 1

    // shift the bits in TEMP over to where we want 'em
    asm("sll     r14, r14, r16");       // 2

    // shift the bits in PTR the other way, so that they
    //   don't collide with those in TEMP
    asm("srl     r2, r2, r1");         // 3

    // mask off the bits in PTR we're going to replace with those from TEMP
    asm("and     r2, r2, r17");        // 4

    // combine the bits in PTR with the bits from TEMP
    asm("or      r2, r2, r14");          // 5

    // update the shift COUNT
    asm("srli    r16, r16, 1");                 // 6

    // shift the MASK
    asm("sll     r14, r17, r16");     // 7

    // update the MASK
    asm("xor     r17, r17, r14");    // 8

    // loop if there's more to do
    asm("bne     r16, r0, fp_reverse_loop");

    //
    // Finally, it turns out the length was given in BITS.  Round-up
    //  to the next byte, and convert to bytes
    //
    asm("addi    r2, r2, 7");      // r_flash_ptr += 7
    asm("srli    r2, r2, 3");      // r_flash_ptr /= 8;

    asm("fp_short_circuit:");
    // Close the EPCS device
    asm("nextpc  r23");
    asm("br      sub_epcs_close");

    // Open it up again (at r_flash_ptr)
    asm("nextpc  r23");
    asm("br      sub_epcs_open_address");

    asm("jmp     r13");
#endif
// end of file



    ////////
    // EPCS_Open_Address
    //
    // "Open-up" the EPCS-device so we can start reading sequential bytes
    // from a given address (the address is 'given' in r_flash_ptr).
    //
    // This is simply a front-end for the sub_tx_rx_int_epcs routine.
    // as such, it doesn't need to fix up a return address.  Instead,
    // it branches directly to sub_tx_rx_int_epcs, and lets the
    // sub-routine return to origional caller.
    //
    //   Register usage:
    //       argument:          r_flash_ptr
    //       temporary:         r_eopen_eclose_tmp
    //       local return ptr:  r_open_close_return_address
    //       return-value:      --none--
    //
    asm("sub_epcs_open_address:");

        // For RTL simulation purposes, this routine can be built to
        // simply return
#ifdef EPCS_SIMULATION_TEST
        // Fix-up return-address  (NOTE: LEAF)
    asm("addi    r23, r23, 4");
        // Return
    asm("jmp     r23");   // Don't worry--we fixed it.
#endif /* EPCS_SIMULATION_TEST */
        // No fix-up, we're just a front-end

        // backup return address
    asm("mov     r22, r23");

        // Check for Device ID and enable 4-byte address mode if its density is
        // greater than 256M bits.
    asm("nextpc  r23");
    asm("br      sub_epcs_config");

    asm("movi    r12, 0x400");//EPCS_CONTROL_SSO_MASK
    asm("stwio   r12, 0x0C (r18)");

    asm("beq     r21, r0, three_bytes_mode");
        /* It is in 4-byte mode.
         * Transmit the READ command first then send the flash address pointer later.
         */
    asm("movi    r11, 0x03");//EPCS_COMMAND_READ

    asm("nextpc  r23");
    asm("br      sub_tx_rx_byte_epcs");

        // r_epcs_tx_value contains 4-bytes address
    asm("mov     r11, r2");

    asm("br      start_tx");

    asm("three_bytes_mode:");
        /*
         * r_epcs_tx_value[31:24]: EPCS_COMMAND_READ
         * r_epcs_tx_value[23:0] : 3-byte address
         */

        // get the read command into our the transmit byte
    asm("movhi   r11,0x0300");// (EPCS_COMMAND_READ << 8)

        // put the flash pointer into the lower 24 bits
    asm("or      r11, r11, r2");

    asm("start_tx:");
        // restore return address
    asm("mov     r23, r22");

        // functionally fall through to the tx_rx_int routine.
    asm("br      sub_tx_rx_int_epcs");

        // The EPCS flash is now open at r_flash_ptr.




        /////////
        // Check the EPCS device ID and enable the 4-byte address mode if
        // it is device with density greater than 256Mbit.
        //
        //   Register usage:
        //       local return ptr:      r_riff_return_address (shared with sub_tx_rx_int_epcs!)
        //       return-value:          r_epcs_4_bytes_mode
        //
  asm("sub_epcs_config:");
            // Fix-up and stash return address
  asm("addi    r8, r23, 4");

            // Clear to 0
  asm("mov    r21, r0");
            // Enable device CS via control-register bit.
  asm("movi    r12, 0x400");
  asm("stwio   r12, 0x0C (r18)");

            // Read the device ID from hardware
  asm("movi    r11, 0x9F");
  asm("nextpc  r23");
  asm("br      sub_tx_rx_byte_epcs");

           // read 3-bytes response
  asm("mov     r11, r0");
  asm("nextpc  r23");
  asm("br      sub_tx_rx_byte_epcs");          // read byte 0

           /* ChinLiang: check whether is Spansion flash or not */
  asm("mov     r17, r0");	/* clear to zero before check */
  asm("movi    r11, 0x01");//EPCS_SPANSION_ID1
  asm("cmpne   r11, r10, r11");
  asm("beq     r11, r0, spansion_flash");

           /* ChinLiang: check the 2nd ID as Spansion have 2 ID */
  asm("movi    r11, 0xEF");// EPCS_SPANSION_ID2
  asm("cmpeq   r11, r10, r11");
  asm("beq     r11, r0, not_spansion_flash");

  asm("spansion_flash:");
           /* ChinLiang: initialize back to r_zero */
  asm("mov     r11, r0");
  asm("movi    r17, 1");	/* ChinLiang: set Spansion flash */

  asm("not_spansion_flash:");

  asm("nextpc  r23");
  asm("br      sub_tx_rx_byte_epcs");          // read byte 1

  asm("nextpc  r23");
  asm("br      sub_tx_rx_byte_epcs");          // read byte 2 (density)

            //disable CS
  asm("stwio   r0, 0x0C (r18)");

           // Check the device density ID
  asm("cmpgeui r10, r10, 0x19");//EPCS_256
  asm("beq     r10, r0, go_return");
#if 0
        enable_four_bytes:

            /* Device more than 256Mbit, enable 4-bytes address mode. */
            movi    r_epcs_4_bytes_mode, 1   /* Set 4-byte mode*/

            /* ChinLiang: check whether its Spansion flash or not */
            bne     r_epcs_spansion_flash, r_zero, enable_four_bytes_spansion

            // Enable device CS via control-register bit.
            movi    r_eopen_eclose_tmp, EPCS_CONTROL_SSO_MASK
            stwio   r_eopen_eclose_tmp, EPCS_CONTROL_OFFSET (r_epcs_base_address)

            movi    r_epcs_tx_value, EPCS_COMMAND_WREN
            nextpc  return_address_less_4
            br      sub_tx_rx_byte_epcs

            //disable CS
            stwio   r_zero, EPCS_CONTROL_OFFSET (r_epcs_base_address)

            // Enable device CS via control-register bit.
            movi    r_eopen_eclose_tmp, EPCS_CONTROL_SSO_MASK
            stwio   r_eopen_eclose_tmp, EPCS_CONTROL_OFFSET (r_epcs_base_address)

            movi    r_epcs_tx_value, EPCS_COMMAND_EN4B
            nextpc  return_address_less_4
            br      sub_tx_rx_byte_epcs

            //disable CS
            stwio   r_zero, EPCS_CONTROL_OFFSET (r_epcs_base_address)
            br      go_return

        enable_four_bytes_spansion:

            // Enable device CS via control-register bit.
            movi    r_eopen_eclose_tmp, EPCS_CONTROL_SSO_MASK
            stwio   r_eopen_eclose_tmp, EPCS_CONTROL_OFFSET (r_epcs_base_address)

            //ChinLiang: using Bank Register Write command
            movi    r_epcs_tx_value, EPCS_COMMAND_BRWR
            nextpc  return_address_less_4
            br      sub_tx_rx_byte_epcs

            //ChinLiang: with value where set EXTADD bit to 1
            movi    r_epcs_tx_value, EPCS_SPANSION_EXTADD
            nextpc  return_address_less_4
            br      sub_tx_rx_byte_epcs

            //disable CS
            stwio   r_zero, EPCS_CONTROL_OFFSET (r_epcs_base_address)
#endif
        asm("go_return:");
        asm("jmp     r8");




    	asm("sub_read_byte_from_flash_epcs:");
    	asm("mov  r11,r0");

            ////////
            // sub_tx_rx_byte_epcs
            //
            // EPCS devices are funny--every time you want to send something, you
            // also recieve something.  Every time you want to recieve something,
            // you must send something.
            //
            // This routine transmits its argument, and returns whatever was
            // recieved as its result.
            //
            // Because this is a boot-copier, and there's not a damned thing we could
            // do or say if we got an error, the possibility of error-conditions is
            // entirely ignored.
            //
            // Register usage:
            //   argument:       r_epcs_tx_value
            //   temporary:      rf_temp
            //   return-value:   r_read_byte_return_value
            //
            asm("sub_tx_rx_byte_epcs:");
                // Fix-up return-address  (NOTE: LEAF)
            asm("addi    r23, r23, 4");

#ifndef EPCS_SIMULATION_TEST
                // Wait until controller is ready for a TX-char, then send it.
            asm("tx_ready_loop:");
            asm("ldwio   r9, 0x08(r18)");
            asm("andi    r9, r9, 0x40");//EPCS_STATUS_TRDY_MASK
            asm("beq     r9, r0, tx_ready_loop");

            asm("stwio   r11, 0x04 (r18)");

                // Wait until an RX-character shows-up, then get it.
            asm("rx_ready_loop:");
            asm("ldwio   r9, 0x08 (r18)");
            asm("andi    r9, r9, 0x80"); //EPCS_STATUS_RRDY_MASK
            asm("beq     r9, r0, rx_ready_loop");

            asm("ldbuio  r10, 0x00(r18)");
            #else /* EPCS_SIMULATION_TEST */
                // For simulation tests, read a byte from the address in r_flash_ptr
                // and increment it to mimic the sequential read nature of an EPCS
                // device. r_flash_ptr in the context of the EPCS bootloader
                // refers to the flash offset within the EPCS device. We'll
                // add this to any flash base specified with the preprocessor.
                // to allow testing with a conventional parallel flash simulation model.
                mov     rf_temp, r_zero
            #ifdef EPCS_SIMULATION_TEST_FLASH_BASE
                movhi   rf_temp, %hi(EPCS_SIMULATION_TEST_FLASH_BASE)
                addi    rf_temp, rf_temp, %lo(EPCS_SIMULATION_TEST_FLASH_BASE)
            #endif
                add     r_flash_ptr, r_flash_ptr, rf_temp

                // Read byte from the flash image & increment pointer for next time
                ldbuio  r_read_byte_return_value, 0(r_flash_ptr)
                addi    r_flash_ptr, r_flash_ptr, 1
            #endif /* EPCS_SIMULATION_TEST */
                // Return
            asm("jmp     r23");   // Don't worry--we fixed it.



                ////////
                // sub_read_int_from_flash_epcs
                //
                // Alternate entry point for epcs_rx_tx.
                //
                //   Zero the epcs_tx_value before falling through to sub_tx_rx_int_epcs.
                //
                asm("sub_read_int_from_flash_epcs:");

                    // This reads the NEXT sequential integer from the EPCS device,
                    // on the assumption that a valid read-command, with address,
                    // has already been sent, and the CS-bit has been left on.
                    //
                    // Zero the word we're transmitting.
                    //
                asm("mov     r11, r0");

                    //
                    // fall through to the sub_tx_rx_int_epcs routine
                    //


                ////////
                // sub_tx_rx_int_epcs
                //
                //   Subroutine which reads writes four bytes to flash while
                //   at the same time reading four bytes.  EPCS does this whether
                //   you like it or not.  The four bytes start at a
                //   not-necessarily-aligned flash offset.
                //
                //   Strangly, this routine writes MSB first, and reads LSB first.
                //   This is required because the EPCS device itself takes commands
                //   (which is the only reason we write to EPCS inside a boot loader)
                //   MSB first, but SOFs and code are organized LSB first.
                //
                //   This routine shares its input argument with the tx_rx_byte
                //   routine.  This is only safe as long as the tx_rx_byte routine
                //   doesn't trash it's argument.
                //
                //   Register usage:
                //      argument:            r_epcs_tx_value
                //      local variable:      r_trie_count
                //      local return ptr:    r_riff_return_address
                //      return-value:        r_read_int_return_value
                //
                asm("sub_tx_rx_int_epcs:");
                    // Fix-up and stash return address
                asm("addi    r8, r23, 4");

                    //
                    // write bytes (MSB first) and read them (LSB first)
                    //

                    // clear the return value
                asm("mov     r6, r0");

                    // number of bytes to tx/rx
                asm("movi    r20, 4");

                asm("trie_loop:");
                    // position the transmit byte
                asm("roli    r11, r11, 8");

                    // tx/rx a byte
                asm("nextpc  r23");
                asm("br      sub_tx_rx_byte_epcs");

                    // put it into the LSB of the result
                asm("or      r6, r6, r10");

                    // rotate the result so that the latest byte is in the MSB,
                    //  moving the other bytes down toward the LSB (no rori)
                asm("roli    r6, r6, 24");

                    // decrement the counter, and loop
                asm("subi    r20, r20, 1");
                asm("bne     r20, r0, trie_loop");

                    // Return.
                asm("jmp     r8");


                ////////
                // EPCS_Close
                //
                // Terminate current EPCS transaction.
                //
                //       local return ptr:  r_open_close_return_address
                //                          (shared with sub_epcs_open_address)
                //
                asm("sub_epcs_close:");
                    // Fix-up and stash return address
                    asm("addi    r22, r23, 4");

                    // For RTL simulation purposes, this routine can be built to
                    // simply return
                #ifndef EPCS_SIMULATION_TEST
                    // Wait until controller says "Transmitter empty."
                asm("close_ready_loop:");
                asm("ldwio   r12, 0x08 (r18)");
                asm("andi    r12, r12, 0x20"); //EPCS_STATUS_TMT_MASK
                asm("beq     r12, r0, close_ready_loop");

                    // Deassert CS by clearing the SSO-bit (write zero to entire register):
                asm("stwio   r0, 0x0C (r18)");

                    // If we entered "4-byte" address mode, exit it. Other IP may expect
                    // the EPCS device to be in conventioanl 3-byte address mode. We're so
                    // nice here in the SCTC, thinking of these things for you.
                asm("beq     r21, r0, close_3_bytes_mode");

                    // Enable device CS via control-register bit.
                asm("movi    r12, 0x400"); //EPCS_CONTROL_SSO_MASK
                asm("stwio   r12, 0x0C (r18)");

                asm("movi    r11, 0x06");//EPCS_COMMAND_WREN
                asm("nextpc  r23");
                asm("br      sub_tx_rx_byte_epcs");

                    //disable CS
                asm("stwio   r0, 0x0C (r18)");

                    // Enable device CS via control-register bit.
                asm("movi    r12, 0x400");//EPCS_CONTROL_SSO_MASK
                asm("stwio   r12, 0x0C (r18)");

                asm("movi    r11, 0xE9");//EPCS_COMMAND_EX4B
                asm("nextpc  r23");
                asm("br      sub_tx_rx_byte_epcs");

                    //disable CS
                asm("stwio   r0, 0x0C (r18)");

                asm("close_3_bytes_mode:");
                #endif /* EPCS_SIMULATION_TEST */

                    // Return
                asm("jmp     r22");   // Don't worry--we fixed it.




//	    	alt_printf("jumping to 0x%x\n\n",jump_address);
//	    	alt_icache_flush_all();
//	    	alt_dcache_flush_all();
	    	asm ( "callr %0" ::"r"(jump_address) );

	while(1)
	{
		IOWR_ALTERA_AVALON_PIO_DATA(PIO_LEDS_BASE, leds);
        leds = ((leds<<1) & 0x0E) | (!(leds>>3) & 0x1);
		usleep(50000);
	}
	return 0;
}








