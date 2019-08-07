#include "xtensa.h"
#include "xtensa_printer.h"

XtensaAssembler::XtensaAssembler(): Assembler() { }
size_t XtensaAssembler::bits() const { return 32; }

void XtensaAssembler::init(const AssemblerRequest &request)
{
    if(request.modeIs("xtensabe"))
        m_decoder = std::make_unique<XtensaDecoder>(Endianness::BigEndian);
    else
        m_decoder = std::make_unique<XtensaDecoder>(Endianness::LittleEndian);
}

bool XtensaAssembler::decodeInstruction(const BufferView &view, Instruction *instruction) { return m_decoder->decode(view, instruction); }
Printer *XtensaAssembler::doCreatePrinter() const { return new XtensaPrinter(); }
