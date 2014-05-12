#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include <set>
#include <iostream>

using namespace llvm;

namespace {
  struct MemTrace : public ModulePass {
  bool runOnModule(Module &M);
    static char ID; 
    MemTrace() : ModulePass(ID) {}

    virtual const char *getPassName() const {
      return "MemTrace";
    }
  };
}

char MemTrace::ID = 0;
static RegisterPass<MemTrace> X("memtrace", "get memory pass", false, false);

bool MemTrace::runOnModule(Module &M) {
    LLVMContext &Context = M.getContext();

    Type *Int32Ty = Type::getInt32Ty(Context);
    Type *Int64Ty = Type::getInt64Ty(Context);
    Type *VoidTy = Type::getVoidTy(Context);
    Value *Zero = ConstantInt::get(Int32Ty, 0);
    Value *One = ConstantInt::get(Int32Ty, 1);

    //添加函数声明
    Constant *showtrace;
    std::vector<llvm::Type*> showArgs;
    showArgs.push_back(Int64Ty);
    showArgs.push_back(Int32Ty);
    ArrayRef<Type*> argsRef(showArgs);
    FunctionType* showType = FunctionType::get(Int32Ty, argsRef, false);
    showtrace = M.getOrInsertFunction("showtrace", showType);
    
    BasicBlock::iterator InsertPos;
/*    
    Function* Main = M.getFunction("main");
    BasicBlock *mainEntryBlock = &Main->getEntryBlock();
    BasicBlock::iterator MInsertPos = mainEntryBlock->getFirstNonPHI();
    while (isa<AllocaInst>(MInsertPos))
            ++MInsertPos;
    std:: vector<Value*> init(0); 
    CallInst::Create(memtrace_init, init,"myinitcall",MInsertPos);
*/
    for (Module::iterator F = M.begin(), E = M.end(); F != E; ++F) {
        if (F->isDeclaration()) continue;
        for (Function::iterator BB = F->begin(), E = F->end(); BB != E; ++BB){
            for(BasicBlock::iterator I = BB->begin(),IE = BB->end();I!= IE;++I){
                if(I->getOpcode()==27 || I->getOpcode()==28){
               // if(LoadInst* loadInst = dyn_cast<LoadInst>(&*I) || StoreInst* storeInst = dyn_cast<StoreInst>(&*I)){
                    Value *MemAddr = I->getOperand((I->getNumOperands()-1));
                    InsertPos = I;
                    ++InsertPos;
                    MemAddr = new PtrToIntInst(MemAddr,Int64Ty,"addrtoint",InsertPos);
                    std::vector<Value*> mop_flush_args;
                    mop_flush_args.push_back(MemAddr);  
                    if (I->getOpcode() == 27) mop_flush_args.push_back(Zero);
                    if (I->getOpcode() == 28) mop_flush_args.push_back(One);
                    CallInst::Create(showtrace,mop_flush_args,"mycall",InsertPos);
                    InsertPos--;
                    I = InsertPos;
                }//endif
            }//outBasic
        }//outfuncton
    }//outmodule
/*
    for (Function::iterator MB = Main->begin(), MBE = Main->end(); MB != MBE; ++MB){
         for(BasicBlock::iterator MI = MB->begin(),MIE = MB->end();MI!= MIE;++MI){
        if(isa<ReturnInst>(MI)){
                std::vector<Value*> exit(0);
                CallInst::Create(memtrace_finish, exit,"myfinishcall",MI);
        }//endif
     }//BBiterator
    }//FunctionIterator*/
    return false;
}//endrunOnModule
