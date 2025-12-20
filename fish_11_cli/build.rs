use vergen::{BuildBuilder, Emitter};

fn main() {
    // Emit the instructions
    let mut emitter = Emitter::default();

    emitter.add_instructions(&BuildBuilder::all_build().unwrap()).unwrap();

    emitter.emit().unwrap();
}
