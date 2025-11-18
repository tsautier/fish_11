use vergen::Emitter;
use vergen::BuildBuilder;

fn main() {
    // Emit the instructions
    let mut emitter = Emitter::default();
    
    emitter.add_instructions(&BuildBuilder::all_build().unwrap()).unwrap();
    
    emitter.emit().unwrap();
}
