#include "SiteMap.h"

#include <cstdlib>
#include <string>
#include <system_error>

#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

namespace mlfuzzz3::sitemap {
namespace {

using llvm::DebugLoc;
using llvm::ICmpInst;
using llvm::Module;

// Идентификатор модуля — это путь к единице трансляции, поэтому в имени
// файла он непригоден как есть. Всё, кроме букв, цифр, точки, минуса и
// подчёркивания, заменяется подчёркиванием; пустой результат заменяется
// словом, чтобы имя файла никогда не оказалось пустым.
std::string SanitizeForFilename(const std::string& id) {
    std::string out;
    out.reserve(id.size());
    for (const char c : id) {
        const bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        out.push_back(plain ? c : '_');
    }
    if (out.empty()) {
        out = "module";
    }
    // Ведущая точка сделала бы файл скрытым: при относительном пути к
    // единице трансляции («.tmp/x.c») имя таблицы начиналось бы с точки,
    // и обычный glob её не видел — проверка уникальности из-за этого один
    // раз объявила «коллизий нет», не найдя ни одной таблицы.
    if (out.front() == '.') {
        out.front() = '_';
    }
    return out;
}

// Побочный файл обязан читаться построчно чем угодно, поэтому разделитель —
// табуляция, а значения от неё очищаются.
std::string NoTabs(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        if (c == '\t' || c == '\n' || c == '\r') {
            c = ' ';
        }
    }
    return out;
}

bool OperandIsConstant(const ICmpInst& cmp, unsigned index) {
    return llvm::isa<llvm::Constant>(cmp.getOperand(index));
}

}  // namespace

void WriteIfRequested(const Module& module, const std::vector<Row>& rows) {
    const char* dir = std::getenv("MLFUZZZ3_SITEMAP_DIR");
    if (dir == nullptr || *dir == '\0' || rows.empty()) {
        return;
    }
    const std::string module_id = module.getModuleIdentifier();
    const std::string path = std::string(dir) + "/" + SanitizeForFilename(module_id) + ".sites.tsv";

    std::error_code ec;
    llvm::raw_fd_ostream out(path, ec, llvm::sys::fs::OF_Text);
    if (ec) {
        return;  // побочный файл не роняет сборку цели
    }

    out << "# mlfuzzz3 site map v1; ключ — ПАРА (module, site_id): нумерация "
           "начинается заново в каждом модуле\n";
    out << "# site_id\tmodule\tfunction\tfile\tline\tcol\tlhs_const\trhs_const\n";
    for (const Row& row : rows) {
        if (row.cmp == nullptr) {
            continue;
        }
        const ICmpInst& cmp = *row.cmp;
        const llvm::Function* fn = cmp.getFunction();
        const std::string fn_name = fn != nullptr ? fn->getName().str() : std::string("-");

        std::string file = "-";
        unsigned line = 0;
        unsigned col = 0;
        if (const DebugLoc& loc = cmp.getDebugLoc()) {
            line = loc.getLine();
            col = loc.getCol();
            if (llvm::DIScope* scope = llvm::dyn_cast_or_null<llvm::DIScope>(loc.getScope())) {
                file = scope->getFilename().str();
            }
        }

        out << row.site_id << '\t' << NoTabs(module_id) << '\t' << NoTabs(fn_name) << '\t'
            << NoTabs(file) << '\t' << line << '\t' << col << '\t'
            << (OperandIsConstant(cmp, 0) ? 1 : 0) << '\t' << (OperandIsConstant(cmp, 1) ? 1 : 0)
            << '\n';
    }
}

}  // namespace mlfuzzz3::sitemap
